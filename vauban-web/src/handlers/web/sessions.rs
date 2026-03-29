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

    use crate::schema::users;

    #[allow(clippy::type_complexity)]
    let session_row: (
        i32, uuid::Uuid, String, uuid::Uuid,
        String, String, uuid::Uuid, String,
        String, String, String, ipnetwork::IpNetwork,
        Option<String>, Option<String>,
        Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>,
        Option<String>, bool, Option<String>,
        i64, i64, i32, chrono::DateTime<chrono::Utc>,
    ) = match proxy_sessions::table
        .inner_join(schema_assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::id.eq(id))
        .select((
            proxy_sessions::id,
            proxy_sessions::uuid,
            users::username,
            users::uuid,
            schema_assets::name,
            schema_assets::hostname,
            schema_assets::uuid,
            schema_assets::asset_type,
            proxy_sessions::session_type,
            proxy_sessions::status,
            proxy_sessions::credential_username,
            proxy_sessions::client_ip,
            proxy_sessions::client_user_agent,
            proxy_sessions::proxy_instance,
            proxy_sessions::connected_at,
            proxy_sessions::disconnected_at,
            proxy_sessions::justification,
            proxy_sessions::is_recorded,
            proxy_sessions::recording_path,
            proxy_sessions::bytes_sent,
            proxy_sessions::bytes_received,
            proxy_sessions::commands_count,
            proxy_sessions::created_at,
        ))
        .first(&mut conn)
        .await
    {
        Ok(data) => data,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(flash.error("Session not found"), "/sessions");
        }
        Err(_) => {
            return flash_redirect(flash.error("Database error. Please try again."), "/sessions");
        }
    };

    let (
        s_id, s_uuid, s_username, s_user_uuid,
        s_asset_name, s_asset_hostname, s_asset_uuid, s_asset_type,
        s_session_type, s_status, s_credential_username, s_client_ip,
        s_client_user_agent, s_proxy_instance,
        s_connected_at, s_disconnected_at,
        s_justification, s_is_recorded, s_recording_path,
        s_bytes_sent, s_bytes_received, s_commands_count, s_created_at,
    ) = session_row;

    let user_uuid_str = s_user_uuid.to_string();

    // For non-admin users, check if they own this session
    if !user_is_admin && user_uuid_str != auth_user.uuid {
        return flash_redirect(
            flash.error("You can only view your own sessions"),
            "/sessions",
        );
    }

    // Calculate duration if connected_at and disconnected_at are present
    let duration = match (s_connected_at, s_disconnected_at) {
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
        (Some(start), None) if s_status == "active" => {
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
        id: s_id,
        uuid: s_uuid.to_string(),
        username: s_username,
        user_uuid: user_uuid_str,
        asset_name: s_asset_name,
        asset_hostname: s_asset_hostname,
        asset_uuid: s_asset_uuid.to_string(),
        asset_type: s_asset_type,
        session_type: s_session_type,
        status: s_status.clone(),
        credential_username: s_credential_username,
        client_ip: s_client_ip.ip().to_string(),
        client_user_agent: s_client_user_agent,
        proxy_instance: s_proxy_instance,
        connected_at: s_connected_at
            .map(|dt| dt.format("%b %d, %Y %H:%M:%S").to_string()),
        disconnected_at: s_disconnected_at
            .map(|dt| dt.format("%b %d, %Y %H:%M:%S").to_string()),
        duration,
        justification: s_justification,
        is_recorded: s_is_recorded,
        recording_path: s_recording_path,
        bytes_sent: s_bytes_sent,
        bytes_received: s_bytes_received,
        commands_count: s_commands_count,
        created_at: s_created_at
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

    use crate::schema::users;

    #[allow(clippy::type_complexity)]
    let recording_row: (
        i32, uuid::Uuid, String, String, String,
        String, Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>, Option<String>,
        i64, i64, i32,
    ) = match proxy_sessions::table
        .inner_join(schema_assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::id.eq(id))
        .filter(proxy_sessions::is_recorded.eq(true))
        .select((
            proxy_sessions::id,
            proxy_sessions::uuid,
            users::username,
            schema_assets::name,
            schema_assets::hostname,
            proxy_sessions::session_type,
            proxy_sessions::connected_at,
            proxy_sessions::disconnected_at,
            proxy_sessions::recording_path,
            proxy_sessions::bytes_sent,
            proxy_sessions::bytes_received,
            proxy_sessions::commands_count,
        ))
        .first(&mut conn)
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

    let (
        r_id, r_uuid, r_username, r_asset_name, r_asset_hostname,
        r_session_type, r_connected_at, r_disconnected_at, r_recording_path,
        r_bytes_sent, r_bytes_received, r_commands_count,
    ) = recording_row;

    // Calculate duration
    let duration = match (r_connected_at, r_disconnected_at) {
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
        session_id: r_id,
        session_uuid: r_uuid.to_string(),
        username: r_username,
        asset_name: r_asset_name,
        asset_hostname: r_asset_hostname,
        session_type: r_session_type,
        connected_at: r_connected_at
            .map(|dt| dt.format("%b %d, %Y %H:%M:%S").to_string()),
        disconnected_at: r_disconnected_at
            .map(|dt| dt.format("%b %d, %Y %H:%M:%S").to_string()),
        duration,
        recording_path: r_recording_path,
        bytes_sent: r_bytes_sent,
        bytes_received: r_bytes_received,
        commands_count: r_commands_count,
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

    use crate::schema::users;

    let mut count_query = proxy_sessions::table
        .filter(proxy_sessions::justification.is_not_null())
        .into_boxed();

    if let Some(ref status) = status_filter {
        count_query = count_query.filter(proxy_sessions::status.eq(status));
    }

    let total_items: i64 = count_query
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);

    let total_pages = ((total_items as f64) / (items_per_page as f64)).ceil() as i32;
    let offset = ((page - 1) * items_per_page) as i64;

    let mut list_query = proxy_sessions::table
        .inner_join(schema_assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::justification.is_not_null())
        .into_boxed();

    if let Some(ref status) = status_filter {
        list_query = list_query.filter(proxy_sessions::status.eq(status));
    }

    #[allow(clippy::type_complexity)]
    let approvals_data: Vec<(
        uuid::Uuid, String, String, String, String,
        Option<String>, ipnetwork::IpNetwork,
        chrono::DateTime<chrono::Utc>, String, Option<i32>,
    )> = list_query
        .select((
            proxy_sessions::uuid,
            users::username,
            schema_assets::hostname,
            schema_assets::asset_type,
            proxy_sessions::session_type,
            proxy_sessions::justification,
            proxy_sessions::client_ip,
            proxy_sessions::created_at,
            proxy_sessions::status,
            proxy_sessions::max_session_duration,
        ))
        .order(proxy_sessions::created_at.desc())
        .limit(items_per_page as i64)
        .offset(offset)
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let approvals: Vec<crate::templates::sessions::approval_list::ApprovalListItem> =
        approvals_data
            .into_iter()
            .map(
                |(uuid, username, asset_name, asset_type, session_type,
                  justification, client_ip, created_at, status, max_session_duration)| {
                    crate::templates::sessions::approval_list::ApprovalListItem {
                        uuid: uuid.to_string(),
                        username,
                        asset_name,
                        asset_type,
                        session_type,
                        justification,
                        client_ip: client_ip.ip().to_string(),
                        created_at: created_at.format("%b %d, %Y %H:%M").to_string(),
                        status,
                        max_session_duration,
                    }
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

    use crate::schema::users;

    #[allow(clippy::type_complexity)]
    let approval_row: (
        uuid::Uuid, String, String, String, String, String,
        String, String, Option<String>, ipnetwork::IpNetwork,
        String, chrono::DateTime<chrono::Utc>, bool, Option<i32>,
    ) = match proxy_sessions::table
        .inner_join(schema_assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::uuid.eq(approval_uuid))
        .select((
            proxy_sessions::uuid,
            users::username,
            users::email,
            schema_assets::name,
            schema_assets::asset_type,
            schema_assets::hostname,
            proxy_sessions::session_type,
            proxy_sessions::status,
            proxy_sessions::justification,
            proxy_sessions::client_ip,
            proxy_sessions::credential_username,
            proxy_sessions::created_at,
            proxy_sessions::is_recorded,
            proxy_sessions::max_session_duration,
        ))
        .first(&mut conn)
        .await
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

    let (
        a_uuid, username, user_email, asset_name, asset_type, asset_hostname,
        session_type, status, justification, client_ip,
        credential_username, created_at, is_recorded, max_session_duration,
    ) = approval_row;

    let approval = crate::templates::sessions::approval_detail::ApprovalDetail {
        uuid: a_uuid.to_string(),
        username,
        user_email,
        asset_name,
        asset_type,
        asset_hostname,
        session_type,
        status,
        justification,
        client_ip: client_ip.ip().to_string(),
        credential_username,
        created_at: created_at.format("%b %d, %Y %H:%M").to_string(),
        is_recorded,
        max_session_duration,
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


/// Form for approval with optional duration override.
#[derive(Debug, serde::Deserialize)]
pub struct ApproveForm {
    pub csrf_token: String,
    pub duration_value: Option<i32>,
    pub duration_unit: Option<String>,
}

impl ApproveForm {
    /// Delegate to the shared resolver in `utils`.
    pub fn resolve_duration_seconds(&self) -> Result<Option<i32>, &'static str> {
        crate::utils::resolve_duration_seconds(
            self.duration_value,
            self.duration_unit.as_deref(),
        )
    }
}

/// Form for access request submission.
#[derive(Debug, serde::Deserialize)]
pub struct AccessRequestForm {
    pub csrf_token: String,
    pub asset_uuid: String,
    pub session_type: String,
    pub justification: Option<String>,
    pub totp_code: Option<String>,
}

/// Submit an access request (JIT flow).
///
/// POST /sessions/request
///
/// Creates a pending proxy_session and notifies admins.
pub async fn submit_access_request(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth_user: WebAuthUser,
    jar: CookieJar,
    Form(form): Form<AccessRequestForm>,
) -> Response {
    let is_htmx = headers.get("HX-Request").is_some();

    let secret = state.config.secret_key.expose_secret().as_bytes();
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return htmx_or_redirect(is_htmx, "Invalid CSRF token", "/assets");
    }

    let asset_uuid = match ::uuid::Uuid::parse_str(&form.asset_uuid) {
        Ok(uuid) => uuid,
        Err(_) => return htmx_or_redirect(is_htmx, "Invalid asset identifier", "/assets"),
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return htmx_or_redirect(is_htmx, "Database connection failed", "/assets");
        }
    };

    use crate::models::asset::Asset;
    use crate::schema::assets::dsl as a;

    let asset: Asset = match a::assets
        .filter(a::uuid.eq(asset_uuid))
        .filter(a::is_deleted.eq(false))
        .first(&mut conn)
        .await
    {
        Ok(asset) => asset,
        Err(_) => return htmx_or_redirect(is_htmx, "Asset not found", "/assets"),
    };

    let user_uuid = match ::uuid::Uuid::parse_str(&auth_user.uuid) {
        Ok(u) => u,
        Err(_) => return htmx_or_redirect(is_htmx, "Invalid user identifier", "/assets"),
    };

    let user_id: i32 = match crate::schema::users::table
        .filter(crate::schema::users::uuid.eq(user_uuid))
        .select(crate::schema::users::id)
        .first(&mut conn)
        .await
    {
        Ok(id) => id,
        Err(_) => return htmx_or_redirect(is_htmx, "User not found", "/assets"),
    };

    // Justification is always required for JIT access requests
    let justification = match form.justification.as_deref() {
        Some(j) if j.trim().len() >= 10 => Some(sanitize(j.trim())),
        _ => {
            return htmx_or_redirect(
                is_htmx,
                "Justification is required (minimum 10 characters)",
                &format!("/assets/{}", form.asset_uuid),
            );
        }
    };

    // Access rule check
    let access_result = if !auth_user.is_superuser && !auth_user.is_staff {
        let result = crate::services::access::can_access_asset(
            state.access_client.as_ref(),
            &mut conn,
            user_id,
            asset.id,
            &form.session_type,
        )
        .await
        .unwrap_or_else(|_| crate::services::access::AccessCheckResult::denied());

        if !result.allowed {
            return htmx_or_redirect(
                is_htmx,
                "No access rule grants you access to this asset",
                "/assets",
            );
        }
        result
    } else {
        crate::services::access::AccessCheckResult {
            allowed: true,
            require_mfa: true,
            require_approval: true,
            max_session_duration: None,
        }
    };

    // MFA verification (if required)
    if access_result.require_mfa {
        match form.totp_code.as_deref() {
            Some(code) if code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()) => {
                let user_uuid_parsed = match uuid::Uuid::parse_str(&auth_user.uuid) {
                    Ok(u) => u,
                    Err(_) => {
                        return htmx_or_redirect(
                            is_htmx,
                            "Invalid user session",
                            &format!("/assets/{}", form.asset_uuid),
                        );
                    }
                };
                let mfa_secret_opt: Option<String> = crate::schema::users::table
                    .filter(crate::schema::users::uuid.eq(user_uuid_parsed))
                    .select(crate::schema::users::mfa_secret)
                    .first::<Option<String>>(&mut conn)
                    .await
                    .unwrap_or(None);

                match mfa_secret_opt {
                    Some(secret) => {
                        let valid = if let Some(ref vault) = state.vault_client
                            && is_encrypted(&secret)
                        {
                            vault.mfa_verify(&secret, code).await.unwrap_or(false)
                        } else {
                            crate::services::auth::AuthService::verify_totp(&secret, code)
                        };
                        if !valid {
                            return htmx_or_redirect(
                                is_htmx,
                                "Invalid MFA code",
                                &format!("/assets/{}", form.asset_uuid),
                            );
                        }
                    }
                    None => {
                        return htmx_or_redirect(
                            is_htmx,
                            "MFA is not configured for your account",
                            &format!("/assets/{}", form.asset_uuid),
                        );
                    }
                }
            }
            _ => {
                return htmx_or_redirect(
                    is_htmx,
                    "MFA code is required (6 digits)",
                    &format!("/assets/{}", form.asset_uuid),
                );
            }
        }
    }

    // Create pending session
    let session_uuid = ::uuid::Uuid::new_v4();
    let client_ip: ipnetwork::IpNetwork = "0.0.0.0/0".parse().unwrap_or_else(|_| {
        ipnetwork::IpNetwork::V4(ipnetwork::Ipv4Network::from(
            std::net::Ipv4Addr::UNSPECIFIED,
        ))
    });

    use crate::models::session::{NewProxySession, SessionType};

    let new_session = NewProxySession {
        uuid: session_uuid,
        user_id,
        asset_id: asset.id,
        credential_id: "pending".to_string(),
        credential_username: "pending".to_string(),
        session_type: SessionType::parse(&form.session_type),
        status: "pending".to_string(),
        client_ip,
        client_user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(String::from),
        proxy_instance: None,
        justification,
        is_recorded: true,
        metadata: serde_json::json!({}),
        max_session_duration: access_result.max_session_duration,
    };

    if let Err(e) = diesel::insert_into(proxy_sessions::table)
        .values(&new_session)
        .execute(&mut conn)
        .await
    {
        tracing::error!(error = %e, "Failed to create pending session");
        return htmx_or_redirect(is_htmx, "Failed to submit access request", "/assets");
    }

    tracing::info!(
        session_uuid = %session_uuid,
        user = %auth_user.username,
        asset = %asset.name,
        "JIT access request submitted"
    );

    // Notify admins via BroadcastService
    let _ = state.broadcast.send(
        &crate::services::broadcast::WsChannel::Notifications,
        crate::services::broadcast::WsMessage::new(
            "jit-notification",
            format!(
                r#"{{"type":"access_request","user":"{}","asset":"{}","uuid":"{}"}}"#,
                auth_user.username, asset.name, session_uuid
            ),
        ),
    ).await;

    if is_htmx {
        let trigger_json = r#"{"showToast": {"message": "Access request submitted. An administrator will review your request.", "type": "success"}}"#.to_string();
        (
            axum::http::StatusCode::OK,
            [
                ("HX-Trigger", trigger_json),
                ("Content-Type", "text/html".to_string()),
            ],
            "",
        )
            .into_response()
    } else {
        Redirect::to("/sessions/my-requests").into_response()
    }
}

/// Approve an access request.
///
/// POST /sessions/approvals/{uuid}/approve
pub async fn approve_access_request(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<ApproveForm>,
) -> AppResult<Response> {
    let flash = incoming_flash.flash();

    let secret = state.config.secret_key.expose_secret().as_bytes();
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return Ok((axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response());
    }

    if !check_rbac(&state, &auth_user, "admin", "view").await {
        return Err(AppError::Authorization(
            "Only administrators can approve requests".to_string(),
        ));
    }

    let duration_override = match form.resolve_duration_seconds() {
        Ok(d) => d,
        Err(msg) => {
            return Ok(flash_redirect(
                flash.error(msg),
                &format!("/sessions/approvals/{}", uuid_str),
            ));
        }
    };

    let session_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|_| AppError::Validation("Invalid request identifier".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let admin_uuid = ::uuid::Uuid::parse_str(&auth_user.uuid)
        .map_err(|_| AppError::Validation("Invalid admin identifier".to_string()))?;

    let admin_id: i32 = crate::schema::users::table
        .filter(crate::schema::users::uuid.eq(admin_uuid))
        .select(crate::schema::users::id)
        .first(&mut conn)
        .await
        .map_err(|_| AppError::NotFound("Admin user not found".to_string()))?;

    let now = chrono::Utc::now();

    let updated = if let Some(seconds) = duration_override {
        diesel::update(
            proxy_sessions::table
                .filter(proxy_sessions::uuid.eq(session_uuid))
                .filter(proxy_sessions::status.eq("pending")),
        )
        .set((
            proxy_sessions::status.eq("approved"),
            proxy_sessions::approved_by_id.eq(Some(admin_id)),
            proxy_sessions::approved_at.eq(Some(now)),
            proxy_sessions::max_session_duration.eq(Some(seconds)),
            proxy_sessions::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await
        .map_err(AppError::Database)?
    } else {
        diesel::update(
            proxy_sessions::table
                .filter(proxy_sessions::uuid.eq(session_uuid))
                .filter(proxy_sessions::status.eq("pending")),
        )
        .set((
            proxy_sessions::status.eq("approved"),
            proxy_sessions::approved_by_id.eq(Some(admin_id)),
            proxy_sessions::approved_at.eq(Some(now)),
            proxy_sessions::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await
        .map_err(AppError::Database)?
    };

    if updated == 0 {
        return Err(AppError::NotFound(
            "Request not found or already processed".to_string(),
        ));
    }

    if let Some(secs) = duration_override {
        tracing::info!(
            session_uuid = %session_uuid,
            approved_by = %auth_user.username,
            duration_override_seconds = secs,
            "JIT access request approved with duration override"
        );
    } else {
        tracing::info!(
            session_uuid = %session_uuid,
            approved_by = %auth_user.username,
            "JIT access request approved"
        );
    }

    // Notify the requester
    let requester_id: Option<i32> = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .select(proxy_sessions::user_id)
        .first(&mut conn)
        .await
        .ok();

    if let Some(uid) = requester_id {
        let user_uuid_str: Option<String> = crate::schema::users::table
            .filter(crate::schema::users::id.eq(uid))
            .select(crate::schema::users::uuid)
            .first::<::uuid::Uuid>(&mut conn)
            .await
            .ok()
            .map(|u| u.to_string());

        if let Some(ref uuid_s) = user_uuid_str {
            let _ = state.broadcast.send(
                &crate::services::broadcast::WsChannel::Notifications,
                crate::services::broadcast::WsMessage::new(
                    "jit-notification",
                    format!(
                        r#"{{"type":"request_approved","session_uuid":"{}","user_uuid":"{}"}}"#,
                        session_uuid, uuid_s
                    ),
                ),
            ).await;
        }
    }

    Ok(Redirect::to(&format!("/sessions/approvals/{}", uuid_str)).into_response())
}

/// Reject an access request.
///
/// POST /sessions/approvals/{uuid}/reject
pub async fn reject_access_request(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
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

    if !check_rbac(&state, &auth_user, "admin", "view").await {
        return Err(AppError::Authorization(
            "Only administrators can reject requests".to_string(),
        ));
    }

    let session_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|_| AppError::Validation("Invalid request identifier".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let updated = diesel::update(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .filter(proxy_sessions::status.eq("pending")),
    )
    .set((
        proxy_sessions::status.eq("rejected"),
        proxy_sessions::updated_at.eq(chrono::Utc::now()),
    ))
    .execute(&mut conn)
    .await
    .map_err(AppError::Database)?;

    if updated == 0 {
        return Err(AppError::NotFound(
            "Request not found or already processed".to_string(),
        ));
    }

    tracing::info!(
        session_uuid = %session_uuid,
        rejected_by = %auth_user.username,
        "JIT access request rejected"
    );

    // Notify the requester
    let requester_id: Option<i32> = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .select(proxy_sessions::user_id)
        .first(&mut conn)
        .await
        .ok();

    if let Some(uid) = requester_id {
        let user_uuid_str: Option<String> = crate::schema::users::table
            .filter(crate::schema::users::id.eq(uid))
            .select(crate::schema::users::uuid)
            .first::<::uuid::Uuid>(&mut conn)
            .await
            .ok()
            .map(|u| u.to_string());

        if let Some(ref uuid_s) = user_uuid_str {
            let _ = state.broadcast.send(
                &crate::services::broadcast::WsChannel::Notifications,
                crate::services::broadcast::WsMessage::new(
                    "jit-notification",
                    format!(
                        r#"{{"type":"request_rejected","session_uuid":"{}","user_uuid":"{}"}}"#,
                        session_uuid, uuid_s
                    ),
                ),
            ).await;
        }
    }

    Ok(Redirect::to(&format!("/sessions/approvals/{}", uuid_str)).into_response())
}

/// Helper to return HTMX toast or redirect depending on request type.
fn htmx_or_redirect(is_htmx: bool, message: &str, redirect_to: &str) -> Response {
    if is_htmx {
        let escaped = message.replace('\\', r"\\").replace('"', r#"\""#);
        let trigger_json = format!(
            r#"{{"showToast": {{"message": "{}", "type": "error"}}}}"#,
            escaped
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
    } else {
        Redirect::to(redirect_to).into_response()
    }
}

/// Cancel a pending access request (user self-service).
///
/// POST /sessions/my-requests/{uuid}/cancel
pub async fn cancel_access_request(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
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

    let session_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|_| AppError::Validation("Invalid request identifier".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let user_uuid = ::uuid::Uuid::parse_str(&auth_user.uuid)
        .map_err(|_| AppError::Validation("Invalid user identifier".to_string()))?;

    let user_id: i32 = crate::schema::users::table
        .filter(crate::schema::users::uuid.eq(user_uuid))
        .select(crate::schema::users::id)
        .first(&mut conn)
        .await
        .map_err(|_| AppError::NotFound("User not found".to_string()))?;

    let updated = diesel::update(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .filter(proxy_sessions::user_id.eq(user_id))
            .filter(proxy_sessions::status.eq("pending")),
    )
    .set((
        proxy_sessions::status.eq("expired"),
        proxy_sessions::updated_at.eq(chrono::Utc::now()),
    ))
    .execute(&mut conn)
    .await
    .map_err(AppError::Database)?;

    if updated == 0 {
        return Err(AppError::NotFound(
            "Request not found or cannot be cancelled".to_string(),
        ));
    }

    tracing::info!(
        session_uuid = %session_uuid,
        user = %auth_user.username,
        "JIT access request cancelled by user"
    );

    Ok(Redirect::to("/sessions/my-requests").into_response())
}

/// My access requests page (user self-service).
///
/// GET /sessions/my-requests
pub async fn my_requests(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("My Requests".to_string(), user.clone())
        .with_current_path("/sessions/my-requests");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let user_uuid = ::uuid::Uuid::parse_str(&auth_user.uuid)
        .map_err(|e| AppError::Validation(format!("Invalid user UUID: {}", e)))?;

    let user_id: i32 = crate::schema::users::table
        .filter(crate::schema::users::uuid.eq(user_uuid))
        .select(crate::schema::users::id)
        .first(&mut conn)
        .await
        .map_err(|_| AppError::NotFound("User not found".to_string()))?;

    use crate::schema::users;

    #[allow(clippy::type_complexity)]
    let requests_data: Vec<(
        uuid::Uuid, String, String, String,
        String, String, Option<String>,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<i32>,
    )> = proxy_sessions::table
        .inner_join(schema_assets::table)
        .left_join(users::table.on(users::id.nullable().eq(proxy_sessions::approved_by_id)))
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::status.eq_any(["pending", "approved", "rejected", "expired"]))
        .select((
            proxy_sessions::uuid,
            schema_assets::name,
            schema_assets::hostname,
            schema_assets::asset_type,
            proxy_sessions::session_type,
            proxy_sessions::status,
            proxy_sessions::justification,
            proxy_sessions::created_at,
            proxy_sessions::approved_at,
            users::username.nullable(),
            proxy_sessions::max_session_duration,
        ))
        .order(proxy_sessions::created_at.desc())
        .limit(50)
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let requests: Vec<crate::templates::sessions::my_requests::MyRequestItem> = requests_data
        .into_iter()
        .map(
            |(uuid, asset_name, asset_hostname, asset_type,
              session_type, status, justification,
              created_at, approved_at, approved_by, max_session_duration)| {
                crate::templates::sessions::my_requests::MyRequestItem {
                    uuid: uuid.to_string(),
                    asset_name,
                    asset_hostname,
                    asset_type,
                    session_type,
                    status,
                    justification,
                    created_at: created_at.format("%b %d, %Y %H:%M").to_string(),
                    approved_at: approved_at.map(|dt| dt.format("%b %d, %Y %H:%M").to_string()),
                    approved_by,
                    max_session_duration,
                }
            },
        )
        .collect();

    let template = crate::templates::sessions::my_requests::MyRequestsTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        requests,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
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

    use crate::schema::users;

    #[allow(clippy::type_complexity)]
    let sessions_data: Vec<(
        uuid::Uuid, String, String, String,
        String, ipnetwork::IpNetwork,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = proxy_sessions::table
        .inner_join(schema_assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::status.eq("active"))
        .filter(proxy_sessions::connected_at.is_not_null())
        .select((
            proxy_sessions::uuid,
            users::username,
            schema_assets::name,
            schema_assets::hostname,
            proxy_sessions::session_type,
            proxy_sessions::client_ip,
            proxy_sessions::connected_at,
        ))
        .order(proxy_sessions::connected_at.desc())
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let sessions: Vec<crate::templates::sessions::active_list::ActiveSessionItem> = sessions_data
        .into_iter()
        .filter_map(
            |(uuid, username, asset_name, asset_hostname, session_type, client_ip, connected_at)| {
                let connected = connected_at?;
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

                Some(crate::templates::sessions::active_list::ActiveSessionItem {
                    uuid: uuid.to_string(),
                    username,
                    asset_name,
                    asset_hostname,
                    session_type,
                    client_ip: client_ip.ip().to_string(),
                    connected_at: connected.format("%H:%M:%S").to_string(),
                    duration: duration_str,
                })
            },
        )
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

/// Serve an SSH asciicast recording file (.cast).
///
/// Route: GET /recordings/{session_uuid}/session.cast
pub async fn serve_ssh_recording(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    axum::extract::Path(session_uuid_str): axum::extract::Path<String>,
) -> Result<axum::response::Response, AppError> {
    use axum::body::Body;
    use axum::http::header;
    use tokio_util::io::ReaderStream;

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
    let cast_relative = format!("{}session.cast", base_dir);

    let supervisor = state
        .supervisor
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Requires supervisor (SCM_RIGHTS)")))?;

    let result = supervisor
        .request_recording_file(&session.uuid.to_string(), &cast_relative)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Supervisor request failed: {}", e)))?;

    if !result.success {
        return Err(AppError::NotFound(format!(
            "Recording not available: {}",
            result.error.unwrap_or_default()
        )));
    }

    let std_file = result.file.ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("Supervisor returned success but no FD"))
    })?;

    let tokio_file = tokio::fs::File::from_std(std_file);
    let stream = ReaderStream::with_capacity(tokio_file, 64 * 1024);

    axum::http::Response::builder()
        .header(header::CONTENT_TYPE, "application/x-asciicast")
        .header(header::CACHE_CONTROL, "private, max-age=3600")
        .body(Body::from_stream(stream))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Response build error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ApproveForm::resolve_duration_seconds tests ----

    fn make_approve_form(value: Option<i32>, unit: Option<&str>) -> ApproveForm {
        ApproveForm {
            csrf_token: "token".to_string(),
            duration_value: value,
            duration_unit: unit.map(String::from),
        }
    }

    #[test]
    fn test_resolve_duration_none_returns_none() {
        let form = make_approve_form(None, None);
        assert_eq!(form.resolve_duration_seconds().unwrap(), None);
    }

    #[test]
    fn test_resolve_duration_hours_converts() {
        let form = make_approve_form(Some(2), Some("hours"));
        assert_eq!(form.resolve_duration_seconds().unwrap(), Some(7200));
    }

    #[test]
    fn test_resolve_duration_minutes_converts() {
        let form = make_approve_form(Some(30), Some("minutes"));
        assert_eq!(form.resolve_duration_seconds().unwrap(), Some(1800));
    }

    #[test]
    fn test_resolve_duration_zero_rejected() {
        let form = make_approve_form(Some(0), Some("minutes"));
        assert!(form.resolve_duration_seconds().is_err());
    }

    #[test]
    fn test_resolve_duration_negative_rejected() {
        let form = make_approve_form(Some(-1), Some("hours"));
        assert!(form.resolve_duration_seconds().is_err());
    }

    #[test]
    fn test_resolve_duration_exceeds_max_rejected() {
        let form = make_approve_form(Some(25), Some("hours"));
        assert!(form.resolve_duration_seconds().is_err());
    }

    #[test]
    fn test_resolve_duration_unknown_unit_rejected() {
        let form = make_approve_form(Some(5), Some("days"));
        assert!(form.resolve_duration_seconds().is_err());
    }

    #[test]
    fn test_resolve_duration_overflow_rejected() {
        let form = make_approve_form(Some(i32::MAX), Some("hours"));
        assert!(form.resolve_duration_seconds().is_err());
    }

    // ---- Range parsing tests ----

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
            codec_string: "avc1.42c01e".to_string(),
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
    fn test_serve_ssh_recording_structural() {
        let source = include_str!("sessions.rs");
        assert!(
            source.contains("fn serve_ssh_recording"),
            "serve_ssh_recording handler must exist"
        );
        assert!(
            source.contains("session.cast"),
            "serve_ssh_recording must reference session.cast"
        );
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
