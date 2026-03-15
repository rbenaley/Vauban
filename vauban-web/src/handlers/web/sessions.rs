/// Session and approval page handlers.
use super::*;
use crate::models::session::SessionType;

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
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

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
    let user_is_admin = check_rbac(&state, &auth_user, "admin", "view").await;

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

    let mut query = proxy_sessions::table
        .inner_join(schema_assets::table)
        .into_boxed();

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
        if let Some(parsed) = SessionType::try_parse(session_type) {
            query = query.filter(proxy_sessions::session_type.eq(parsed));
        } else {
            // Invalid session type filter: return no results
            query = query.filter(proxy_sessions::id.eq(-1));
        }
    }

    if let Some(ref asset) = asset_filter
        && !asset.is_empty()
    {
        let pattern = crate::db::like_contains(asset);
        query = query.filter(schema_assets::name.ilike(pattern));
    }

    #[allow(clippy::type_complexity)]
    let db_sessions: Vec<(
        i32,
        uuid::Uuid,
        String,
        String,
        SessionType,
        String,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        bool,
    )> = query
        .select((
            proxy_sessions::id,
            proxy_sessions::uuid,
            schema_assets::name,
            schema_assets::hostname,
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
                    session_type: session_type.to_string(),
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
    let user_is_admin = check_rbac(&state, &auth_user, "admin", "view").await;

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
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

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
    if !check_rbac(&state, &auth_user, "admin", "view").await {
        return Err(AppError::Authorization(
            "Only administrators can view recordings".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Recordings".to_string(), user.clone())
        .with_current_path("/sessions/recordings");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    // Load recordings from database (sessions with is_recorded = true)
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let format_filter = params.get("format").cloned();
    let asset_filter = params.get("asset").cloned();

    let mut query = proxy_sessions::table
        .inner_join(schema_assets::table)
        .filter(proxy_sessions::is_recorded.eq(true))
        .filter(proxy_sessions::recording_path.is_not_null())
        .into_boxed();

    if let Some(ref session_type) = format_filter
        && !session_type.is_empty()
    {
        if let Some(parsed) = SessionType::try_parse(session_type) {
            query = query.filter(proxy_sessions::session_type.eq(parsed));
        } else {
            // Invalid format filter: return no results
            query = query.filter(proxy_sessions::id.eq(-1));
        }
    }

    if let Some(ref asset) = asset_filter
        && !asset.is_empty()
    {
        let pattern = crate::db::like_contains(asset);
        query = query.filter(schema_assets::name.ilike(pattern));
    }

    #[allow(clippy::type_complexity)]
    let db_recordings: Vec<(
        i32,
        String,
        SessionType,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
    )> = query
        .select((
            proxy_sessions::id,
            schema_assets::name,
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
                    session_type: session_type.to_string(),
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
    if !check_rbac(&state, &auth_user, "admin", "view").await {
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
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

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
    if !check_rbac(&state, &auth_user, "admin", "view").await {
        return Err(AppError::Authorization(
            "Only administrators can view approvals".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Approvals".to_string(), user.clone())
        .with_current_path("/sessions/approvals");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

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
    if !check_rbac(&state, &auth_user, "admin", "view").await {
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
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

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
    if !check_rbac(&state, &auth_user, "admin", "view").await {
        return Err(AppError::Authorization(
            "Only administrators can view active sessions".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Active Sessions".to_string(), user.clone())
        .with_current_path("/sessions/active");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

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

/// Serve an MP4 recording file for a given session UUID.
///
/// The file is obtained from the supervisor via SCM_RIGHTS (read-only FD),
/// so vauban-web never needs filesystem access to the recordings directory.
///
/// Supports HTTP Range requests for seeking in the browser video player.
/// Memory usage is constant (~64 KB) regardless of file size thanks to
/// chunked streaming via `ReaderStream`.
pub async fn serve_recording(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    headers: axum::http::HeaderMap,
    axum::extract::Path(session_uuid_str): axum::extract::Path<String>,
) -> Result<axum::response::Response, AppError> {
    use axum::body::Body;
    use axum::http::{StatusCode, header};
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    use tokio_util::io::ReaderStream;

    if !check_rbac(&state, &auth_user, "admin", "view").await {
        return Err(AppError::Authorization(
            "Only administrators can access recordings".to_string(),
        ));
    }

    let clean_uuid = session_uuid_str
        .strip_suffix(".mp4")
        .unwrap_or(&session_uuid_str);
    let session_uuid = ::uuid::Uuid::parse_str(clean_uuid)
        .map_err(|_| AppError::Validation("Invalid session UUID".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    use crate::schema::proxy_sessions::dsl;
    let session: crate::models::session::ProxySession = dsl::proxy_sessions
        .filter(dsl::uuid.eq(session_uuid))
        .first(&mut conn)
        .await
        .map_err(|_| AppError::NotFound("Session not found".to_string()))?;

    if !session.is_recorded {
        return Err(AppError::NotFound(
            "No recording for this session".to_string(),
        ));
    }

    let recording_path = session
        .recording_path
        .as_deref()
        .ok_or_else(|| AppError::NotFound("Recording path not set".to_string()))?;

    let storage_base = &state.config.recording.storage_path;
    let relative_path = recording_path
        .strip_prefix(storage_base)
        .unwrap_or(recording_path)
        .trim_start_matches('/');

    let supervisor = state.supervisor.as_ref().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "Recording playback requires supervisor (SCM_RIGHTS)"
        ))
    })?;

    let result = supervisor
        .request_recording_file(&session.uuid.to_string(), relative_path)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Supervisor request failed: {}", e)))?;

    if !result.success {
        return Err(AppError::NotFound(format!(
            "Recording file not available: {}",
            result.error.unwrap_or_default()
        )));
    }

    let std_file = result.file.ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "Supervisor returned success but no file descriptor"
        ))
    })?;

    let metadata = std_file
        .metadata()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to read file metadata: {}", e)))?;
    let file_size = metadata.len();

    let mut tokio_file = tokio::fs::File::from_std(std_file);

    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| parse_range_header(s, file_size));

    let common_headers = [
        (header::CONTENT_TYPE, "video/mp4".to_string()),
        (header::ACCEPT_RANGES, "bytes".to_string()),
        (
            header::CONTENT_DISPOSITION,
            format!("inline; filename=\"{}.mp4\"", clean_uuid),
        ),
        (header::CACHE_CONTROL, "private, max-age=3600".to_string()),
    ];

    const CHUNK_SIZE: usize = 64 * 1024;

    if let Some((start, end)) = range {
        let length = end - start + 1;

        tokio_file
            .seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Seek failed: {}", e)))?;

        let limited = tokio_file.take(length);
        let stream = ReaderStream::with_capacity(limited, CHUNK_SIZE);

        let mut builder = axum::http::Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_LENGTH, length.to_string())
            .header(
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, end, file_size),
            );

        for (k, v) in &common_headers {
            builder = builder.header(k, v.as_str());
        }

        builder
            .body(Body::from_stream(stream))
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Response build error: {}", e)))
    } else {
        let stream = ReaderStream::with_capacity(tokio_file, CHUNK_SIZE);

        let mut builder = axum::http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, file_size.to_string());

        for (k, v) in &common_headers {
            builder = builder.header(k, v.as_str());
        }

        builder
            .body(Body::from_stream(stream))
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Response build error: {}", e)))
    }
}

/// Parse an HTTP Range header value (e.g. "bytes=1234-5678" or "bytes=1234-").
/// Returns the inclusive byte range `(start, end)` clamped to `file_size`.
fn parse_range_header(header: &str, file_size: u64) -> Option<(u64, u64)> {
    let range_spec = header.strip_prefix("bytes=")?;
    let (start_str, end_str) = range_spec.split_once('-')?;

    let start: u64 = start_str.parse().ok()?;
    if start >= file_size {
        return None;
    }

    let end: u64 = if end_str.is_empty() {
        file_size - 1
    } else {
        end_str.parse::<u64>().ok()?.min(file_size - 1)
    };

    if end < start {
        return None;
    }

    Some((start, end))
}

/// Metadata for a recording segment (deserialized from meta.json).
#[derive(serde::Deserialize)]
struct SegmentMeta {
    index: u32,
    width: u16,
    height: u16,
    duration_ticks: u64,
    init_size: u64,
    file_size: u64,
    codec_string: String,
}

/// Wrapper for meta.json deserialization.
#[derive(serde::Deserialize)]
struct RecordingMeta {
    segments: Vec<SegmentMeta>,
}

const DASH_TIMESCALE: u32 = 90_000;

/// Generate a DASH MPD manifest for a segmented recording.
///
/// Each segment becomes a DASH Period with its own resolution and codec
/// parameters. Shaka Player uses this to drive MSE-based playback with
/// seamless resolution transitions.
pub async fn serve_manifest(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    axum::extract::Path(session_uuid_str): axum::extract::Path<String>,
) -> Result<axum::response::Response, AppError> {
    use axum::body::Body;
    use axum::http::{StatusCode, header};

    if !check_rbac(&state, &auth_user, "admin", "view").await {
        return Err(AppError::Authorization(
            "Only administrators can access recordings".to_string(),
        ));
    }

    let session_uuid = ::uuid::Uuid::parse_str(&session_uuid_str)
        .map_err(|_| AppError::Validation("Invalid session UUID".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    use crate::schema::proxy_sessions::dsl;
    let session: crate::models::session::ProxySession = dsl::proxy_sessions
        .filter(dsl::uuid.eq(session_uuid))
        .first(&mut conn)
        .await
        .map_err(|_| AppError::NotFound("Session not found".to_string()))?;

    if !session.is_recorded {
        return Err(AppError::NotFound(
            "No recording for this session".to_string(),
        ));
    }

    let recording_path = session
        .recording_path
        .as_deref()
        .ok_or_else(|| AppError::NotFound("Recording path not set".to_string()))?;

    let storage_base = &state.config.recording.storage_path;
    let base_dir = recording_path
        .strip_prefix(storage_base)
        .unwrap_or(recording_path)
        .trim_start_matches('/');
    let meta_relative = format!("{}meta.json", base_dir);

    let supervisor = state
        .supervisor
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Requires supervisor (SCM_RIGHTS)")))?;

    let result = supervisor
        .request_recording_file(&session.uuid.to_string(), &meta_relative)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Supervisor request failed: {}", e)))?;

    if !result.success {
        return Err(AppError::NotFound(format!(
            "meta.json not available: {}",
            result.error.unwrap_or_default()
        )));
    }

    let meta_file = result.file.ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("Supervisor returned success but no FD"))
    })?;

    let mut tokio_file = tokio::fs::File::from_std(meta_file);
    let mut json_buf = String::new();
    {
        use tokio::io::AsyncReadExt;
        tokio_file
            .read_to_string(&mut json_buf)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to read meta.json: {}", e)))?;
    }

    let meta: RecordingMeta = serde_json::from_str(&json_buf)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid meta.json: {}", e)))?;

    let mpd = build_mpd_xml(&session_uuid_str, &meta.segments);

    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/dash+xml")
        .header(header::CACHE_CONTROL, "private, max-age=3600")
        .body(Body::from(mpd))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Response build error: {}", e)))
}

/// Build DASH MPD XML from segment metadata.
///
/// Uses the `isoff-main` profile with `SegmentList` and explicit byte ranges
/// for initialization and media data. This avoids the `sidx` box requirement
/// of the `isoff-on-demand` profile (our fMP4 writer does not produce `sidx`).
fn build_mpd_xml(session_uuid: &str, segments: &[SegmentMeta]) -> String {
    let total_duration_ticks: u64 = segments.iter().map(|s| s.duration_ticks).sum();
    let total_seconds = total_duration_ticks as f64 / f64::from(DASH_TIMESCALE);
    let total_hours = (total_seconds / 3600.0).floor() as u64;
    let total_mins = ((total_seconds % 3600.0) / 60.0).floor() as u64;
    let total_secs = total_seconds % 60.0;
    let iso_duration = format!("PT{total_hours}H{total_mins}M{total_secs:.3}S");

    let mut xml = String::with_capacity(2048);
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<MPD xmlns=\"urn:mpeg:dash:schema:mpd:2011\" \
         type=\"static\" \
         mediaPresentationDuration=\"{iso_duration}\" \
         minBufferTime=\"PT2S\" \
         profiles=\"urn:mpeg:dash:profile:isoff-main:2011\">\n"
    ));

    for seg in segments {
        let seg_seconds = seg.duration_ticks as f64 / f64::from(DASH_TIMESCALE);
        let seg_hours = (seg_seconds / 3600.0).floor() as u64;
        let seg_mins = ((seg_seconds % 3600.0) / 60.0).floor() as u64;
        let seg_secs = seg_seconds % 60.0;
        let seg_iso = format!("PT{seg_hours}H{seg_mins}M{seg_secs:.3}S");

        let init_end = seg.init_size.saturating_sub(1);

        xml.push_str(&format!(
            "  <Period id=\"{idx}\" duration=\"{seg_iso}\">\n",
            idx = seg.index
        ));
        xml.push_str("    <AdaptationSet mimeType=\"video/mp4\" startWithSAP=\"1\">\n");
        xml.push_str(&format!(
            "      <Representation id=\"{idx}\" codecs=\"{codec}\" \
             width=\"{w}\" height=\"{h}\" bandwidth=\"500000\">\n",
            idx = seg.index,
            codec = seg.codec_string,
            w = seg.width,
            h = seg.height,
        ));
        xml.push_str(&format!(
            "        <BaseURL>/recordings/{session_uuid}/{idx:03}.mp4</BaseURL>\n",
            idx = seg.index,
        ));
        let media_end = seg.file_size.saturating_sub(1);
        xml.push_str(&format!(
            "        <SegmentList>\n\
             \x20         <Initialization range=\"0-{init_end}\"/>\n\
             \x20         <SegmentURL mediaRange=\"{media_start}-{media_end}\"/>\n\
             \x20       </SegmentList>\n",
            media_start = seg.init_size,
        ));
        xml.push_str("      </Representation>\n");
        xml.push_str("    </AdaptationSet>\n");
        xml.push_str("  </Period>\n");
    }

    xml.push_str("</MPD>\n");
    xml
}

/// Serve a single segment file from a segmented recording.
///
/// Route: GET /recordings/{session_uuid}/{segment}.mp4
pub async fn serve_segment(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    headers: axum::http::HeaderMap,
    axum::extract::Path((session_uuid_str, segment_str)): axum::extract::Path<(String, String)>,
) -> Result<axum::response::Response, AppError> {
    use axum::body::Body;
    use axum::http::{StatusCode, header};
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    use tokio_util::io::ReaderStream;

    if !check_rbac(&state, &auth_user, "admin", "view").await {
        return Err(AppError::Authorization(
            "Only administrators can access recordings".to_string(),
        ));
    }

    let session_uuid = ::uuid::Uuid::parse_str(&session_uuid_str)
        .map_err(|_| AppError::Validation("Invalid session UUID".to_string()))?;

    let segment_name = segment_str.strip_suffix(".mp4").unwrap_or(&segment_str);
    if segment_name.is_empty() || !segment_name.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::Validation("Invalid segment index".to_string()));
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    use crate::schema::proxy_sessions::dsl;
    let session: crate::models::session::ProxySession = dsl::proxy_sessions
        .filter(dsl::uuid.eq(session_uuid))
        .first(&mut conn)
        .await
        .map_err(|_| AppError::NotFound("Session not found".to_string()))?;

    if !session.is_recorded {
        return Err(AppError::NotFound(
            "No recording for this session".to_string(),
        ));
    }

    let recording_path = session
        .recording_path
        .as_deref()
        .ok_or_else(|| AppError::NotFound("Recording path not set".to_string()))?;

    let storage_base = &state.config.recording.storage_path;
    let base_dir = recording_path
        .strip_prefix(storage_base)
        .unwrap_or(recording_path)
        .trim_start_matches('/');
    let segment_relative = format!("{}{}.mp4", base_dir, segment_name);

    let supervisor = state
        .supervisor
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Requires supervisor (SCM_RIGHTS)")))?;

    let result = supervisor
        .request_recording_file(&session.uuid.to_string(), &segment_relative)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Supervisor request failed: {}", e)))?;

    if !result.success {
        return Err(AppError::NotFound(format!(
            "Segment not available: {}",
            result.error.unwrap_or_default()
        )));
    }

    let std_file = result.file.ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("Supervisor returned success but no FD"))
    })?;

    let metadata = std_file
        .metadata()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to read file metadata: {}", e)))?;
    let file_size = metadata.len();

    let mut tokio_file = tokio::fs::File::from_std(std_file);

    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| parse_range_header(s, file_size));

    let common_headers = [
        (header::CONTENT_TYPE, "video/mp4".to_string()),
        (header::ACCEPT_RANGES, "bytes".to_string()),
        (header::CACHE_CONTROL, "private, max-age=3600".to_string()),
    ];

    const CHUNK_SIZE: usize = 64 * 1024;

    if let Some((start, end)) = range {
        let length = end - start + 1;

        tokio_file
            .seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Seek failed: {}", e)))?;

        let limited = tokio_file.take(length);
        let stream = ReaderStream::with_capacity(limited, CHUNK_SIZE);

        let mut builder = axum::http::Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_LENGTH, length.to_string())
            .header(
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, end, file_size),
            );

        for (k, v) in &common_headers {
            builder = builder.header(k, v.as_str());
        }

        builder
            .body(Body::from_stream(stream))
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Response build error: {}", e)))
    } else {
        let stream = ReaderStream::with_capacity(tokio_file, CHUNK_SIZE);

        let mut builder = axum::http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, file_size.to_string());

        for (k, v) in &common_headers {
            builder = builder.header(k, v.as_str());
        }

        builder
            .body(Body::from_stream(stream))
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Response build error: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE_SIZE: u64 = 10_000_000;

    #[test]
    fn test_range_open_ended() {
        assert_eq!(
            parse_range_header("bytes=0-", FILE_SIZE),
            Some((0, FILE_SIZE - 1))
        );
        assert_eq!(
            parse_range_header("bytes=5000000-", FILE_SIZE),
            Some((5_000_000, FILE_SIZE - 1))
        );
    }

    #[test]
    fn test_range_closed() {
        assert_eq!(parse_range_header("bytes=0-999", FILE_SIZE), Some((0, 999)));
        assert_eq!(
            parse_range_header("bytes=100-200", FILE_SIZE),
            Some((100, 200))
        );
    }

    #[test]
    fn test_range_clamped_to_file_size() {
        assert_eq!(
            parse_range_header("bytes=0-99999999", FILE_SIZE),
            Some((0, FILE_SIZE - 1))
        );
    }

    #[test]
    fn test_range_start_at_last_byte() {
        assert_eq!(
            parse_range_header("bytes=9999999-", FILE_SIZE),
            Some((FILE_SIZE - 1, FILE_SIZE - 1))
        );
    }

    #[test]
    fn test_range_start_beyond_file_size() {
        assert_eq!(parse_range_header("bytes=10000000-", FILE_SIZE), None);
        assert_eq!(parse_range_header("bytes=99999999-", FILE_SIZE), None);
    }

    #[test]
    fn test_range_end_before_start() {
        assert_eq!(parse_range_header("bytes=500-100", FILE_SIZE), None);
    }

    #[test]
    fn test_range_invalid_prefix() {
        assert_eq!(parse_range_header("chars=0-100", FILE_SIZE), None);
        assert_eq!(parse_range_header("0-100", FILE_SIZE), None);
    }

    #[test]
    fn test_range_non_numeric() {
        assert_eq!(parse_range_header("bytes=abc-def", FILE_SIZE), None);
        assert_eq!(parse_range_header("bytes=-100", FILE_SIZE), None);
    }

    #[test]
    fn test_range_empty_file() {
        assert_eq!(parse_range_header("bytes=0-", 0), None);
    }

    #[test]
    fn test_range_single_byte_file() {
        assert_eq!(parse_range_header("bytes=0-", 1), Some((0, 0)));
        assert_eq!(parse_range_header("bytes=0-0", 1), Some((0, 0)));
        assert_eq!(parse_range_header("bytes=1-", 1), None);
    }

    fn make_segment(
        index: u32,
        w: u16,
        h: u16,
        duration_ticks: u64,
        init_size: u64,
        file_size: u64,
    ) -> SegmentMeta {
        SegmentMeta {
            index,
            width: w,
            height: h,
            duration_ticks,
            init_size,
            file_size,
            codec_string: format!("avc1.42c01e"),
        }
    }

    #[test]
    fn test_mpd_single_period() {
        let segments = vec![make_segment(1, 1280, 720, 900_000, 512, 4096)];
        let mpd = build_mpd_xml("test-uuid", &segments);

        assert!(mpd.contains("<?xml version=\"1.0\""));
        assert!(mpd.contains("<MPD"));
        assert!(mpd.contains("type=\"static\""));
        assert!(mpd.contains("isoff-main"));
        assert!(mpd.contains("<Period id=\"1\""));
        assert!(!mpd.contains("<Period id=\"2\""));
        assert!(mpd.contains("width=\"1280\""));
        assert!(mpd.contains("height=\"720\""));
        assert!(mpd.contains("codecs=\"avc1.42c01e\""));
        assert!(mpd.contains("/recordings/test-uuid/001.mp4"));
        assert!(mpd.contains("<SegmentList>"));
        assert!(mpd.contains("Initialization range=\"0-511\""));
        assert!(mpd.contains("mediaRange=\"512-4095\""));
    }

    #[test]
    fn test_mpd_multi_period() {
        let segments = vec![
            make_segment(1, 1280, 720, 450_000, 512, 4096),
            make_segment(2, 1920, 1080, 900_000, 640, 8192),
            make_segment(3, 800, 600, 225_000, 480, 2048),
        ];
        let mpd = build_mpd_xml("multi-uuid", &segments);

        assert!(mpd.contains("<Period id=\"1\""));
        assert!(mpd.contains("<Period id=\"2\""));
        assert!(mpd.contains("<Period id=\"3\""));
        assert!(mpd.contains("width=\"1280\""));
        assert!(mpd.contains("width=\"1920\""));
        assert!(mpd.contains("width=\"800\""));
        assert!(mpd.contains("/recordings/multi-uuid/001.mp4"));
        assert!(mpd.contains("/recordings/multi-uuid/002.mp4"));
        assert!(mpd.contains("/recordings/multi-uuid/003.mp4"));
    }

    #[test]
    fn test_mpd_byte_ranges() {
        let segments = vec![make_segment(1, 1920, 1080, 900_000, 1024, 65536)];
        let mpd = build_mpd_xml("range-uuid", &segments);

        assert!(mpd.contains("Initialization range=\"0-1023\""));
        assert!(mpd.contains("mediaRange=\"1024-65535\""));
    }
}
