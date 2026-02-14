/// Session and approval page handlers.
use super::*;

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

    let mut query = proxy_sessions::table.inner_join(schema_assets::table).into_boxed();

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
        let pattern = crate::db::like_contains(asset);
        query = query.filter(schema_assets::name.ilike(pattern));
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
        .inner_join(schema_assets::table)
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
        let pattern = crate::db::like_contains(asset);
        query = query.filter(schema_assets::name.ilike(pattern));
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
