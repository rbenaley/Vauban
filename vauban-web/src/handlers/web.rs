/// VAUBAN Web - Web page handlers.
///
/// Handlers for serving HTML pages using Askama templates.
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
};
use diesel::prelude::*;
use std::collections::HashMap;

use crate::AppState;
use crate::db::get_connection;
use crate::error::AppError;
use crate::middleware::auth::{AuthUser, OptionalAuthUser};
use crate::schema::{assets, proxy_sessions};
use crate::templates::accounts::{
    GroupDetailTemplate, GroupListTemplate, LoginTemplate, MfaSetupTemplate, ProfileTemplate,
    UserDetailTemplate, UserListTemplate,
};
use crate::templates::assets::asset_list::AssetListItem;
use crate::templates::assets::{
    AccessListTemplate, AssetDetailTemplate, AssetGroupDetailTemplate, AssetGroupEditTemplate,
    AssetGroupListTemplate, AssetListTemplate,
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
    auth_user: AuthUser,
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
    auth_user: AuthUser,
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

    if let Some(ref search) = search_filter {
        if !search.is_empty() {
            let pattern = format!("%{}%", search);
            query = query.filter(
                users::username
                    .ilike(pattern.clone())
                    .or(users::email.ilike(pattern.clone()))
                    .or(users::first_name.ilike(pattern.clone()))
                    .or(users::last_name.ilike(pattern)),
            );
        }
    }

    if let Some(ref status) = status_filter {
        match status.as_str() {
            "active" => query = query.filter(users::is_active.eq(true)),
            "inactive" => query = query.filter(users::is_active.eq(false)),
            _ => {}
        }
    }

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
    auth_user: AuthUser,
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
    State(_state): State<AppState>,
    auth_user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
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
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// MFA setup page.
pub async fn mfa_setup(
    State(_state): State<AppState>,
    auth_user: AuthUser,
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

/// Asset list page.
pub async fn asset_list(
    State(state): State<AppState>,
    auth_user: AuthUser,
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

    if let Some(ref search) = search_filter {
        if !search.is_empty() {
            let pattern = format!("%{}%", search);
            query = query.filter(
                assets::name
                    .ilike(pattern.clone())
                    .or(assets::hostname.ilike(pattern)),
            );
        }
    }

    if let Some(ref asset_type) = type_filter {
        if !asset_type.is_empty() {
            query = query.filter(assets::asset_type.eq(asset_type));
        }
    }

    if let Some(ref status) = status_filter {
        if !status.is_empty() {
            query = query.filter(assets::status.eq(status));
        }
    }

    let db_assets: Vec<(i32, String, String, i32, String, String)> = query
        .select((
            assets::id,
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
            |(id, name, hostname, port, asset_type, status)| AssetListItem {
                id,
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

/// Asset detail page.
pub async fn asset_detail(
    State(state): State<AppState>,
    auth_user: AuthUser,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));

    let mut conn = get_connection(&state.db_pool)?;

    // Query asset details with optional group info
    let asset_data: AssetQueryDetailResult = diesel::sql_query(format!(
        "SELECT a.uuid, a.name, a.hostname, a.ip_address, a.port, a.asset_type, a.status,
                g.name as group_name, g.uuid::text as group_uuid,
                a.description, a.os_type, a.os_version, a.require_mfa, a.require_justification,
                a.max_session_duration, a.last_seen, a.created_at, a.updated_at
         FROM assets a
         LEFT JOIN asset_groups g ON g.id = a.group_id
         WHERE a.id = {} AND a.is_deleted = false",
        id
    ))
    .get_result(&mut conn)
    .map_err(|e| match e {
        diesel::result::Error::NotFound => AppError::NotFound("Asset not found".to_string()),
        _ => AppError::Database(e),
    })?;

    let asset = crate::templates::assets::asset_detail::AssetDetail {
        uuid: asset_data.uuid.to_string(),
        name: asset_data.name.clone(),
        hostname: asset_data.hostname,
        ip_address: asset_data.ip_address,
        port: asset_data.port,
        asset_type: asset_data.asset_type,
        status: asset_data.status,
        group_name: asset_data.group_name,
        group_uuid: asset_data.group_uuid,
        description: asset_data.description,
        os_type: asset_data.os_type,
        os_version: asset_data.os_version,
        require_mfa: asset_data.require_mfa,
        require_justification: asset_data.require_justification,
        max_session_duration: asset_data.max_session_duration,
        last_seen: asset_data
            .last_seen
            .map(|dt| dt.format("%b %d, %Y %H:%M").to_string()),
        created_at: asset_data.created_at.format("%b %d, %Y %H:%M").to_string(),
        updated_at: asset_data.updated_at.format("%b %d, %Y %H:%M").to_string(),
    };

    let base = BaseTemplate::new(format!("{} - Asset", asset_data.name), user.clone())
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

/// Helper struct for asset detail query results.
#[derive(diesel::QueryableByName)]
struct AssetQueryDetailResult {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    uuid: ::uuid::Uuid,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    hostname: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    ip_address: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Int4)]
    port: i32,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_type: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    status: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Varchar>)]
    group_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    group_uuid: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    description: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Varchar>)]
    os_type: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Varchar>)]
    os_version: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    require_mfa: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    require_justification: bool,
    #[diesel(sql_type = diesel::sql_types::Int4)]
    max_session_duration: i32,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
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
    auth_user: AuthUser,
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

    if let Some(ref status) = status_filter {
        if !status.is_empty() {
            query = query.filter(proxy_sessions::status.eq(status));
        }
    }

    if let Some(ref session_type) = type_filter {
        if !session_type.is_empty() {
            query = query.filter(proxy_sessions::session_type.eq(session_type));
        }
    }

    if let Some(ref asset) = asset_filter {
        if !asset.is_empty() {
            let pattern = format!("%{}%", asset);
            query = query.filter(assets::name.ilike(pattern));
        }
    }

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

/// Session detail page.
pub async fn session_detail(
    State(state): State<AppState>,
    auth_user: AuthUser,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::sessions::session_detail::SessionDetail;

    let user = Some(user_context_from_auth(&auth_user));
    let mut conn = get_connection(&state.db_pool)?;

    // Query session details with user and asset info
    let session_data: SessionQueryDetailResult = diesel::sql_query(format!(
        "SELECT ps.id, ps.uuid, u.username, u.uuid::text as user_uuid,
                a.name as asset_name, a.hostname as asset_hostname, a.uuid::text as asset_uuid, a.asset_type,
                ps.session_type, ps.status, ps.credential_username, ps.client_ip::text as client_ip,
                ps.client_user_agent, ps.proxy_instance, ps.connected_at, ps.disconnected_at,
                ps.justification, ps.is_recorded, ps.recording_path, ps.bytes_sent, ps.bytes_received,
                ps.commands_count, ps.created_at
         FROM proxy_sessions ps
         INNER JOIN users u ON u.id = ps.user_id
         INNER JOIN assets a ON a.id = ps.asset_id
         WHERE ps.id = {}",
        id
    ))
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
    auth_user: AuthUser,
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

    if let Some(ref session_type) = format_filter {
        if !session_type.is_empty() {
            query = query.filter(proxy_sessions::session_type.eq(session_type));
        }
    }

    if let Some(ref asset) = asset_filter {
        if !asset.is_empty() {
            let pattern = format!("%{}%", asset);
            query = query.filter(assets::name.ilike(pattern));
        }
    }

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
    auth_user: AuthUser,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::sessions::recording_play::RecordingData;

    let user = Some(user_context_from_auth(&auth_user));
    let mut conn = get_connection(&state.db_pool)?;

    // Query session/recording details
    let recording_data: RecordingQueryResult = diesel::sql_query(format!(
        "SELECT ps.id, ps.uuid, u.username, a.name as asset_name, a.hostname as asset_hostname,
                ps.session_type, ps.connected_at, ps.disconnected_at, ps.recording_path,
                ps.bytes_sent, ps.bytes_received, ps.commands_count
         FROM proxy_sessions ps
         INNER JOIN users u ON u.id = ps.user_id
         INNER JOIN assets a ON a.id = ps.asset_id
         WHERE ps.id = {} AND ps.is_recorded = true",
        id
    ))
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
    auth_user: AuthUser,
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

    // Build query with optional status filter
    let status_clause = if let Some(ref s) = status_filter {
        format!("AND ps.status = '{}'", s.replace('\'', "''"))
    } else {
        String::new()
    };

    // Count total items
    let total_items: i64 = diesel::sql_query(format!(
        "SELECT COUNT(*) as count FROM proxy_sessions ps WHERE ps.justification IS NOT NULL {}",
        status_clause
    ))
    .get_result::<ApprovalCountResult>(&mut conn)
    .map(|r| r.count)
    .unwrap_or(0);

    let total_pages = ((total_items as f64) / (items_per_page as f64)).ceil() as i32;
    let offset = (page - 1) * items_per_page;

    // Query approvals with joins
    let approvals_data: Vec<ApprovalQueryResult> = diesel::sql_query(format!(
        "SELECT ps.uuid, u.username, a.hostname as asset_name, a.asset_type, ps.session_type, 
                ps.justification, ps.client_ip::text as client_ip, ps.created_at, ps.status
         FROM proxy_sessions ps
         INNER JOIN users u ON u.id = ps.user_id
         INNER JOIN assets a ON a.id = ps.asset_id
         WHERE ps.justification IS NOT NULL {}
         ORDER BY ps.created_at DESC
         LIMIT {} OFFSET {}",
        status_clause, items_per_page, offset
    ))
    .load(&mut conn)
    .map_err(|e| AppError::Database(e))?;

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
    auth_user: AuthUser,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));

    let mut conn = get_connection(&state.db_pool)?;
    let approval_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    // Query approval details with joins
    let approval_data: ApprovalDetailResult = diesel::sql_query(format!(
        "SELECT ps.uuid, u.username, u.email as user_email, a.name as asset_name, a.asset_type, 
                a.hostname as asset_hostname, ps.session_type, ps.status, ps.justification, 
                ps.client_ip::text as client_ip, ps.credential_username, ps.created_at, ps.is_recorded
         FROM proxy_sessions ps
         INNER JOIN users u ON u.id = ps.user_id
         INNER JOIN assets a ON a.id = ps.asset_id
         WHERE ps.uuid = '{}'",
        approval_uuid
    ))
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
    auth_user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Active Sessions".to_string(), user.clone())
        .with_current_path("/sessions/active");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let mut conn = get_connection(&state.db_pool)?;

    // Query active sessions with joins
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
    .map_err(|e| AppError::Database(e))?;

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
    auth_user: AuthUser,
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
    let groups_data: Vec<(
        ::uuid::Uuid,
        String,
        Option<String>,
        String,
        chrono::DateTime<chrono::Utc>,
    )> = if let Some(ref s) = search_filter {
        diesel::sql_query(format!(
            "SELECT g.uuid, g.name, g.description, g.source, g.created_at
             FROM vauban_groups g
             WHERE g.name ILIKE '%{}%' OR g.description ILIKE '%{}%'
             ORDER BY g.name ASC",
            s.replace('\'', "''"),
            s.replace('\'', "''")
        ))
        .load::<GroupQueryResult>(&mut conn)
        .map_err(|e| AppError::Database(e))?
        .into_iter()
        .map(|r| (r.uuid, r.name, r.description, r.source, r.created_at))
        .collect()
    } else {
        diesel::sql_query(
            "SELECT g.uuid, g.name, g.description, g.source, g.created_at
             FROM vauban_groups g
             ORDER BY g.name ASC",
        )
        .load::<GroupQueryResult>(&mut conn)
        .map_err(|e| AppError::Database(e))?
        .into_iter()
        .map(|r| (r.uuid, r.name, r.description, r.source, r.created_at))
        .collect()
    };

    // Get member counts
    let group_items: Vec<crate::templates::accounts::group_list::GroupListItem> = groups_data
        .into_iter()
        .map(|(uuid, name, description, source, created_at)| {
            // Get member count for this group
            let member_count: i64 = diesel::sql_query(format!(
                "SELECT COUNT(*) as count FROM user_groups ug
                 INNER JOIN vauban_groups g ON g.id = ug.group_id
                 WHERE g.uuid = '{}'",
                uuid
            ))
            .get_result::<CountResult>(&mut conn)
            .map(|r| r.count)
            .unwrap_or(0);

            crate::templates::accounts::group_list::GroupListItem {
                uuid: uuid.to_string(),
                name,
                description,
                source,
                member_count,
                created_at: created_at.format("%b %d, %Y").to_string(),
            }
        })
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

/// Helper struct for group query results.
#[derive(diesel::QueryableByName)]
struct GroupQueryResult {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    uuid: ::uuid::Uuid,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    description: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    source: String,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Helper struct for count results.
#[derive(diesel::QueryableByName)]
struct CountResult {
    #[diesel(sql_type = diesel::sql_types::Int8)]
    count: i64,
}

/// Group detail page.
pub async fn group_detail(
    State(state): State<AppState>,
    auth_user: AuthUser,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));

    let mut conn = get_connection(&state.db_pool)?;
    let group_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    // Query group details
    let group_data: GroupQueryResult = diesel::sql_query(format!(
        "SELECT uuid, name, description, source, created_at
         FROM vauban_groups WHERE uuid = '{}'",
        group_uuid
    ))
    .get_result(&mut conn)
    .map_err(|e| match e {
        diesel::result::Error::NotFound => AppError::NotFound("Group not found".to_string()),
        _ => AppError::Database(e),
    })?;

    // Get additional fields with a second query
    let group_extra: GroupExtraResult = diesel::sql_query(format!(
        "SELECT external_id, updated_at, last_synced
         FROM vauban_groups WHERE uuid = '{}'",
        group_uuid
    ))
    .get_result(&mut conn)
    .map_err(|e| AppError::Database(e))?;

    // Query group members
    let members_data: Vec<GroupMemberResult> = diesel::sql_query(format!(
        "SELECT u.uuid, u.username, u.email, u.first_name, u.last_name, u.is_active
         FROM users u
         INNER JOIN user_groups ug ON ug.user_id = u.id
         INNER JOIN vauban_groups g ON g.id = ug.group_id
         WHERE g.uuid = '{}' AND u.is_deleted = false
         ORDER BY u.username",
        group_uuid
    ))
    .load(&mut conn)
    .map_err(|e| AppError::Database(e))?;

    let members: Vec<crate::templates::accounts::group_detail::GroupMember> = members_data
        .into_iter()
        .map(|m| {
            let full_name = match (m.first_name, m.last_name) {
                (Some(f), Some(l)) => Some(format!("{} {}", f, l)),
                (Some(f), None) => Some(f),
                (None, Some(l)) => Some(l),
                (None, None) => None,
            };
            crate::templates::accounts::group_detail::GroupMember {
                uuid: m.uuid.to_string(),
                username: m.username,
                email: m.email,
                full_name,
                is_active: m.is_active,
            }
        })
        .collect();

    let group = crate::templates::accounts::group_detail::GroupDetail {
        uuid: group_data.uuid.to_string(),
        name: group_data.name.clone(),
        description: group_data.description,
        source: group_data.source,
        external_id: group_extra.external_id,
        created_at: group_data.created_at.format("%b %d, %Y %H:%M").to_string(),
        updated_at: group_extra.updated_at.format("%b %d, %Y %H:%M").to_string(),
        last_synced: group_extra
            .last_synced
            .map(|dt| dt.format("%b %d, %Y %H:%M").to_string()),
        members,
    };

    let base = BaseTemplate::new(format!("{} - Group", group_data.name), user.clone())
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

/// Helper struct for group extra fields.
#[derive(diesel::QueryableByName)]
struct GroupExtraResult {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Varchar>)]
    external_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    last_synced: Option<chrono::DateTime<chrono::Utc>>,
}

/// Helper struct for group member query results.
#[derive(diesel::QueryableByName)]
struct GroupMemberResult {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    uuid: ::uuid::Uuid,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    username: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    email: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Varchar>)]
    first_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Varchar>)]
    last_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    is_active: bool,
}

/// Access rules list page.
pub async fn access_rules_list(
    State(_state): State<AppState>,
    auth_user: AuthUser,
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
    auth_user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Asset Groups".to_string(), user.clone())
        .with_current_path("/assets/groups");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let mut conn = get_connection(&state.db_pool)?;
    let search_filter = params.get("search").cloned();

    // Query asset groups
    let groups_data: Vec<AssetGroupQueryResult> = if let Some(ref s) = search_filter {
        diesel::sql_query(format!(
            "SELECT g.uuid, g.name, g.slug, g.description, g.color, g.icon, g.created_at,
                    (SELECT COUNT(*) FROM assets a WHERE a.group_id = g.id AND a.is_deleted = false) as asset_count
             FROM asset_groups g
             WHERE g.is_deleted = false AND (g.name ILIKE '%{}%' OR g.slug ILIKE '%{}%')
             ORDER BY g.name ASC",
            s.replace('\'', "''"),
            s.replace('\'', "''")
        ))
        .load(&mut conn)
        .map_err(|e| AppError::Database(e))?
    } else {
        diesel::sql_query(
            "SELECT g.uuid, g.name, g.slug, g.description, g.color, g.icon, g.created_at,
                    (SELECT COUNT(*) FROM assets a WHERE a.group_id = g.id AND a.is_deleted = false) as asset_count
             FROM asset_groups g
             WHERE g.is_deleted = false
             ORDER BY g.name ASC"
        )
        .load(&mut conn)
        .map_err(|e| AppError::Database(e))?
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
    auth_user: AuthUser,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));

    let mut conn = get_connection(&state.db_pool)?;
    let group_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    // Query group details
    let group_data: AssetGroupDetailResult = diesel::sql_query(format!(
        "SELECT uuid, name, slug, description, color, icon, created_at, updated_at
         FROM asset_groups WHERE uuid = '{}' AND is_deleted = false",
        group_uuid
    ))
    .get_result(&mut conn)
    .map_err(|e| match e {
        diesel::result::Error::NotFound => AppError::NotFound("Asset group not found".to_string()),
        _ => AppError::Database(e),
    })?;

    // Query assets in this group
    let assets_data: Vec<GroupAssetResult> = diesel::sql_query(format!(
        "SELECT a.uuid, a.name, a.hostname, a.asset_type, a.status
         FROM assets a
         INNER JOIN asset_groups g ON g.id = a.group_id
         WHERE g.uuid = '{}' AND a.is_deleted = false
         ORDER BY a.name ASC",
        group_uuid
    ))
    .load(&mut conn)
    .map_err(|e| AppError::Database(e))?;

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
    auth_user: AuthUser,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));

    let mut conn = get_connection(&state.db_pool)?;
    let group_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    // Query group details for editing
    let group_data: AssetGroupEditResult = diesel::sql_query(format!(
        "SELECT uuid, name, slug, description, color, icon
         FROM asset_groups WHERE uuid = '{}' AND is_deleted = false",
        group_uuid
    ))
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
    .with_current_path("/assets/groups");
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
    Ok(Html(html))
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
}

/// Update asset group handler.
pub async fn update_asset_group(
    State(state): State<AppState>,
    _auth_user: AuthUser,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    axum::extract::Form(form): axum::extract::Form<UpdateAssetGroupForm>,
) -> Result<impl IntoResponse, AppError> {
    let mut conn = get_connection(&state.db_pool)?;
    let group_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    // Update the group
    diesel::sql_query(format!(
        "UPDATE asset_groups SET name = '{}', slug = '{}', description = {}, color = '{}', icon = '{}', updated_at = NOW()
         WHERE uuid = '{}' AND is_deleted = false",
        form.name.replace('\'', "''"),
        form.slug.replace('\'', "''"),
        form.description.as_ref().map(|d| format!("'{}'", d.replace('\'', "''"))).unwrap_or_else(|| "NULL".to_string()),
        form.color.replace('\'', "''"),
        form.icon.replace('\'', "''"),
        group_uuid
    ))
    .execute(&mut conn)
    .map_err(|e| AppError::Database(e))?;

    // Redirect back to the group detail page
    Ok(axum::response::Redirect::to(&format!(
        "/assets/groups/{}",
        group_uuid
    )))
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
        let json = r##"{"name": "Production Servers", "slug": "production-servers", "description": "All production servers", "color": "#ff5733", "icon": "server"}"##;

        let form: UpdateAssetGroupForm = serde_json::from_str(json).unwrap();

        assert_eq!(form.name, "Production Servers");
        assert_eq!(form.slug, "production-servers");
        assert_eq!(form.description, Some("All production servers".to_string()));
        assert_eq!(form.color, "#ff5733");
        assert_eq!(form.icon, "server");
    }

    #[test]
    fn test_update_asset_group_form_deserialize_minimal() {
        let json = r##"{"name": "Test", "slug": "test", "color": "#fff", "icon": "folder"}"##;

        let form: UpdateAssetGroupForm = serde_json::from_str(json).unwrap();

        assert_eq!(form.name, "Test");
        assert_eq!(form.slug, "test");
        assert!(form.description.is_none());
        assert_eq!(form.color, "#fff");
        assert_eq!(form.icon, "folder");
    }

    #[test]
    fn test_update_asset_group_form_deserialize_with_null_description() {
        let json = r##"{"name": "Group", "slug": "group", "description": null, "color": "#000", "icon": "box"}"##;

        let form: UpdateAssetGroupForm = serde_json::from_str(json).unwrap();

        assert!(form.description.is_none());
    }

    #[test]
    fn test_update_asset_group_form_deserialize_special_chars() {
        let json = r##"{"name": "Test's Group", "slug": "tests-group", "description": "Description with quotes", "color": "#123456", "icon": "database"}"##;

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
        };

        let debug_str = format!("{:?}", form);

        assert!(debug_str.contains("UpdateAssetGroupForm"));
        assert!(debug_str.contains("Debug Test"));
    }

    #[test]
    fn test_update_asset_group_form_missing_required_field() {
        // Missing 'icon' field
        let json = r##"{"name": "Test", "slug": "test", "color": "#fff"}"##;

        let result: Result<UpdateAssetGroupForm, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_asset_group_form_empty_strings() {
        let json = r#"{"name": "", "slug": "", "color": "", "icon": ""}"#;

        let form: UpdateAssetGroupForm = serde_json::from_str(json).unwrap();

        // Empty strings are valid for deserialization (validation is separate)
        assert_eq!(form.name, "");
        assert_eq!(form.slug, "");
    }
}
