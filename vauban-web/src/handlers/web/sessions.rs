/// Session and approval page handlers.
use super::*;
use crate::models::session::SessionType;

/// Statuses that belong to the approval lifecycle. Session-state
/// statuses (connecting, active, terminated, disconnected) are
/// excluded — they belong in the session list, not the approval queue.
const APPROVAL_STATUSES: &[&str] = &[
    "pending", "approved", "rejected", "revoked", "expired", "orphaned",
];

/// Session list page (admin-only).
pub async fn session_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    if !perms.admin_view {
        return Err(AppError::Authorization(
            "Only administrators can view all sessions".to_string(),
        ));
    }

    use crate::templates::sessions::session_list::SessionListItem;

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Sessions".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/sessions");
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

    const SESSIONS_PER_PAGE: i64 = 30;

    let page: i32 = params
        .get("page")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1)
        .max(1);

    // Build base filters as a closure to apply to both count and data queries
    use crate::schema::users;
    use crate::services::session_history::{SessionHistoryDbRow, SessionHistoryRow};

    let mut query = proxy_sessions::table
        .inner_join(schema_assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .into_boxed();
    let mut count_query = proxy_sessions::table
        .inner_join(schema_assets::table)
        .into_boxed();

    // Exclude pending approval requests
    query = query.filter(proxy_sessions::status.ne("pending"));
    query = query.filter(proxy_sessions::status.ne("orphaned"));
    count_query = count_query.filter(proxy_sessions::status.ne("pending"));
    count_query = count_query.filter(proxy_sessions::status.ne("orphaned"));

    // Industrial kill-switch (layer 2): when `industrial.enabled =
    // false`, IACS tunnel sessions drop out of the operational
    // `/sessions` history list at the DB level. Applied to BOTH the
    // data and count queries so pagination stays in lock-step (mirror
    // of the user-zone assets list in `handlers::web::assets`). A
    // hand-crafted `?type=iacs_tunnel` is rendered inert by this
    // `ne(IacsTunnel)` clause even though the type filter still
    // parses. Forensic surfaces (`/sessions/recordings`, `/audit`)
    // are intentionally NOT gated -- yesterday's audit trail survives
    // switching IACS off.
    if !state.config.industrial.enabled {
        query = query.filter(proxy_sessions::session_type.ne(SessionType::IacsTunnel));
        count_query = count_query.filter(proxy_sessions::session_type.ne(SessionType::IacsTunnel));
    }

    if let Some(ref status) = status_filter
        && !status.is_empty()
    {
        query = query.filter(proxy_sessions::status.eq(status));
        count_query = count_query.filter(proxy_sessions::status.eq(status));
    }

    if let Some(ref session_type) = type_filter
        && !session_type.is_empty()
    {
        if let Some(parsed) = SessionType::try_parse(session_type) {
            query = query.filter(proxy_sessions::session_type.eq(parsed));
            count_query = count_query.filter(proxy_sessions::session_type.eq(parsed));
        } else {
            query = query.filter(proxy_sessions::id.eq(-1));
            count_query = count_query.filter(proxy_sessions::id.eq(-1));
        }
    }

    if let Some(ref asset) = asset_filter
        && !asset.is_empty()
    {
        let pattern = crate::db::like_contains(asset);
        query = query.filter(schema_assets::name.ilike(pattern.clone()));
        count_query = count_query.filter(schema_assets::name.ilike(pattern));
    }

    let total_items: i64 = count_query.count().get_result(&mut conn).await.unwrap_or(0);

    let total_pages = ((total_items as f64) / (SESSIONS_PER_PAGE as f64))
        .ceil()
        .max(1.0) as i32;
    let page = page.min(total_pages);
    let offset = ((page - 1) as i64) * SESSIONS_PER_PAGE;

    let db_sessions: Vec<SessionHistoryDbRow> = query
        .select((
            proxy_sessions::id,
            proxy_sessions::uuid,
            schema_assets::name,
            schema_assets::hostname,
            proxy_sessions::session_type,
            proxy_sessions::status,
            proxy_sessions::credential_id,
            proxy_sessions::credential_username,
            proxy_sessions::tunnel_target_addr,
            proxy_sessions::connected_at,
            proxy_sessions::disconnected_at,
            proxy_sessions::is_recorded,
            proxy_sessions::recording_path,
            users::username,
            proxy_sessions::created_at,
        ))
        .order(proxy_sessions::created_at.desc())
        .limit(SESSIONS_PER_PAGE)
        .offset(offset)
        .load(&mut conn)
        .await?;

    let now = chrono::Utc::now();
    let sessions: Vec<SessionListItem> = db_sessions
        .into_iter()
        .map(SessionHistoryRow::from)
        .map(|row| row.into_list_item(now))
        .collect();

    use crate::templates::accounts::user_list::Pagination;

    let start_index = if total_items > 0 { offset + 1 } else { 0 };
    let end_index = (offset + SESSIONS_PER_PAGE).min(total_items);

    let pagination = if total_items > 0 {
        Some(Pagination {
            current_page: page,
            total_pages,
            total_items: total_items as i32,
            items_per_page: SESSIONS_PER_PAGE as i32,
            has_previous: page > 1,
            has_next: page < total_pages,
            start_index: start_index as i32,
            end_index: end_index as i32,
        })
    } else {
        None
    };

    let has_filters = status_filter.is_some() || type_filter.is_some() || asset_filter.is_some();
    let ws_enabled = !has_filters && page == 1;

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
        show_view_link: true,
        pagination,
        ws_enabled,
        industrial_enabled: state.config.industrial.enabled,
        tz: browser_tz.0,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Terminate a session from the web UI.
///
/// Two callers share this endpoint:
///
/// 1. The HTMX `<form hx-post="/sessions/{uuid}/terminate">` button on
///    `/sessions/active` -- the API helper returns an HTML fragment
///    that swaps the session row in place. We pass it through
///    unchanged.
/// 2. The plain `<form method="post">` Disconnect button on the IACS
///    tunnel status page (`/sessions/{uuid}/iacs/status`). A regular
///    form submit makes the browser navigate to the response, so
///    returning the API JSON would dump raw `{ "id": ..., "uuid":
///    ..., ... }` into the address bar (the user-reported bug). For
///    that flow we translate the API outcome into a flash + 303
///    redirect to `/sessions` (POST-Redirect-GET).
#[allow(clippy::too_many_arguments)]
// allow-ungated: instance authorization via services::session_access::verify (owner OR sessions:write)
pub async fn terminate_session_web(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    jar: CookieJar,
    incoming_flash: IncomingFlash,
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

    let is_htmx = headers.get("HX-Request").is_some();
    let flash = incoming_flash.flash();

    if ::uuid::Uuid::parse_str(&session_uuid_str).is_err() {
        if is_htmx {
            return Ok(Redirect::to("/sessions/active").into_response());
        }
        return Ok(flash_redirect(
            flash.error("Invalid session identifier"),
            "/sessions/active",
        ));
    }

    let api_result = crate::handlers::api::sessions::terminate_session(
        State(state),
        headers,
        auth_user.0,
        perms,
        axum::extract::Path(session_uuid_str),
    )
    .await;

    if is_htmx {
        return api_result;
    }

    // Browser flow (non-HTMX): a regular `<form method="post">` would
    // otherwise navigate to the API JSON body. Translate the outcome
    // into a flash + redirect so the user lands back on a real page.
    match api_result {
        Ok(_) => Ok(flash_redirect(
            flash.success("Session terminated"),
            "/sessions",
        )),
        Err(AppError::NotFound(_)) => Ok(flash_redirect(
            flash.error("Session not found"),
            "/sessions",
        )),
        Err(AppError::Validation(msg)) => Ok(flash_redirect(flash.error(&msg), "/sessions")),
        Err(e) => Err(e),
    }
}

/// Session detail page.
pub async fn session_detail(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
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
    // Sourced from the request-scoped PermissionContext (Casbin via middleware).
    let user_is_admin = perms.admin_view;

    use crate::schema::users;

    #[allow(clippy::type_complexity)]
    let session_row: (
        i32,
        uuid::Uuid,
        String,
        uuid::Uuid,
        String,
        String,
        uuid::Uuid,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        ipnetwork::IpNetwork,
        Option<String>,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        bool,
        Option<String>,
        i64,
        i64,
        i32,
        chrono::DateTime<chrono::Utc>,
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
            proxy_sessions::credential_id,
            proxy_sessions::credential_username,
            proxy_sessions::tunnel_target_addr,
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
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/sessions",
            );
        }
    };

    let (
        s_id,
        s_uuid,
        s_username,
        s_user_uuid,
        s_asset_name,
        s_asset_hostname,
        s_asset_uuid,
        s_asset_type,
        s_session_type,
        s_status,
        s_credential_id,
        s_credential_username,
        s_tunnel_target_addr,
        s_client_ip,
        s_client_user_agent,
        s_proxy_instance,
        s_connected_at,
        s_disconnected_at,
        s_justification,
        s_is_recorded,
        s_recording_path,
        s_bytes_sent,
        s_bytes_received,
        s_commands_count,
        s_created_at,
    ) = session_row;

    let user_uuid_str = s_user_uuid.to_string();
    let _ = user_is_admin;

    // SECURITY (anti-IDOR + access-rule recheck): delegate the
    // decision to the single session_access seam. The previous
    // ownership check (`!user_is_admin && user_uuid_str !=
    // auth_user.uuid`) ignored the access-rule re-check entirely
    // and used `admin_view` as a coarse override; the new path
    // uses the same trio (vauban-access RPC + Casbin OR-overrides
    // + anti-enum collapse) that protects the rest of the surface.
    {
        use crate::services::session_access::{self, SessionAccessOutcome};
        use shared::messages::SessionAccessIntent;
        match session_access::verify(
            &state,
            &s_uuid.to_string(),
            &auth_user.0,
            &perms,
            SessionAccessIntent::ReadMetadata,
        )
        .await
        {
            SessionAccessOutcome::Allowed => {}
            SessionAccessOutcome::Denied404 | SessionAccessOutcome::DeniedGone => {
                return flash_redirect(flash.error("Session not found"), "/sessions");
            }
        }
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
        credential_id: s_credential_id,
        credential_username: s_credential_username,
        tunnel_target_addr: s_tunnel_target_addr,
        client_ip: s_client_ip.ip().to_string(),
        client_user_agent: s_client_user_agent,
        proxy_instance: s_proxy_instance,
        connected_at: s_connected_at
            .map(|dt| crate::utils::format_local_with_seconds(dt, browser_tz.0)),
        disconnected_at: s_disconnected_at
            .map(|dt| crate::utils::format_local_with_seconds(dt, browser_tz.0)),
        duration,
        justification: s_justification,
        is_recorded: s_is_recorded,
        recording_path: s_recording_path,
        bytes_sent: s_bytes_sent,
        bytes_received: s_bytes_received,
        commands_count: s_commands_count,
        created_at: crate::utils::format_local_with_seconds(s_created_at, browser_tz.0),
        created_at_raw: s_created_at,
        connected_at_raw: s_connected_at,
        disconnected_at_raw: s_disconnected_at,
    };

    let base = BaseTemplate::new(format!("Session #{}", id), user.clone(), browser_tz.0)
        .with_current_path("/sessions");
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
        show_approval_link: user_is_admin,
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
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::schema::users;
    use crate::templates::sessions::recording_list::RecordingListItem;

    // Only admin users (superuser or staff) can view recordings
    if !perms.admin_view {
        return Err(AppError::Authorization(
            "Only administrators can view recordings".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Recordings".to_string(), user.clone(), browser_tz.0)
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

    const RECORDINGS_PER_PAGE: i64 = 30;

    let format_filter = params.get("format").cloned();
    let asset_filter = params.get("asset").cloned();

    let page: i32 = params
        .get("page")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1)
        .max(1);

    let mut query = proxy_sessions::table
        .inner_join(schema_assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::is_recorded.eq(true))
        .filter(proxy_sessions::recording_path.is_not_null())
        .into_boxed();
    let mut count_query = proxy_sessions::table
        .inner_join(schema_assets::table)
        .filter(proxy_sessions::is_recorded.eq(true))
        .filter(proxy_sessions::recording_path.is_not_null())
        .into_boxed();

    if let Some(ref session_type) = format_filter
        && !session_type.is_empty()
    {
        if let Some(parsed) = SessionType::try_parse(session_type) {
            query = query.filter(proxy_sessions::session_type.eq(parsed));
            count_query = count_query.filter(proxy_sessions::session_type.eq(parsed));
        } else {
            query = query.filter(proxy_sessions::id.eq(-1));
            count_query = count_query.filter(proxy_sessions::id.eq(-1));
        }
    }

    if let Some(ref asset) = asset_filter
        && !asset.is_empty()
    {
        let pattern = crate::db::like_contains(asset);
        query = query.filter(schema_assets::name.ilike(pattern.clone()));
        count_query = count_query.filter(schema_assets::name.ilike(pattern));
    }

    let total_items: i64 = count_query.count().get_result(&mut conn).await.unwrap_or(0);
    let total_pages = ((total_items as f64) / (RECORDINGS_PER_PAGE as f64))
        .ceil()
        .max(1.0) as i32;
    let page = page.min(total_pages);
    let offset = ((page - 1) as i64) * RECORDINGS_PER_PAGE;

    #[allow(clippy::type_complexity)]
    let db_recordings: Vec<(
        i32,
        ::uuid::Uuid,
        String,
        SessionType,
        String,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<i64>,
    )> = query
        .select((
            proxy_sessions::id,
            proxy_sessions::uuid,
            schema_assets::name,
            proxy_sessions::session_type,
            proxy_sessions::credential_username,
            users::username,
            proxy_sessions::connected_at,
            proxy_sessions::disconnected_at,
            proxy_sessions::recording_path,
            proxy_sessions::recording_size_bytes,
        ))
        .order(proxy_sessions::created_at.desc())
        .limit(RECORDINGS_PER_PAGE)
        .offset(offset)
        .load(&mut conn)
        .await?;

    let recordings: Vec<RecordingListItem> = db_recordings
        .into_iter()
        .map(
            |(
                id,
                session_uuid,
                asset_name,
                session_type,
                credential_username,
                requester_username,
                connected_at,
                disconnected_at,
                recording_path,
                recording_size_bytes,
            )| {
                let duration_seconds = match (connected_at, disconnected_at) {
                    (Some(start), Some(end)) => {
                        Some(end.signed_duration_since(start).num_seconds())
                    }
                    _ => None,
                };
                let session_type_str = session_type.to_string();
                RecordingListItem {
                    id,
                    session_id: id,
                    session_uuid: session_uuid.to_string(),
                    asset_name,
                    session_type: session_type_str,
                    // Raw values: the identity rendering (pair, arrow,
                    // IACS placeholder) is computed by the template
                    // helpers via the presentation seam.
                    credential_username,
                    requester_username,
                    connected_at: connected_at
                        .map(|dt| crate::utils::format_local(dt, browser_tz.0)),
                    duration_seconds,
                    size_human: recording_size_bytes.map(|b| {
                        crate::templates::sessions::recording_detail::format_bytes_human(b)
                    }),
                    recording_path: recording_path.unwrap_or_default(),
                    status: "ready".to_string(),
                    show_play_recording: session_type != SessionType::IacsTunnel,
                    show_inspect_capture: session_type == SessionType::IacsTunnel,
                }
            },
        )
        .collect();

    use crate::templates::accounts::user_list::Pagination as RecPagination;

    let start_index = if total_items > 0 { offset + 1 } else { 0 };
    let end_index = (offset + RECORDINGS_PER_PAGE).min(total_items);

    let pagination = if total_items > 0 {
        Some(RecPagination {
            current_page: page,
            total_pages,
            total_items: total_items as i32,
            items_per_page: RECORDINGS_PER_PAGE as i32,
            has_previous: page > 1,
            has_next: page < total_pages,
            start_index: start_index as i32,
            end_index: end_index as i32,
        })
    } else {
        None
    };

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
        pagination,
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
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
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
    if !perms.admin_view {
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
        i32,
        uuid::Uuid,
        String,
        String,
        String,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        i64,
        i64,
        i32,
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
        r_id,
        r_uuid,
        r_username,
        r_asset_name,
        r_asset_hostname,
        r_session_type,
        r_connected_at,
        r_disconnected_at,
        r_recording_path,
        r_bytes_sent,
        r_bytes_received,
        r_commands_count,
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
            .map(|dt| crate::utils::format_local_with_seconds(dt, browser_tz.0)),
        disconnected_at: r_disconnected_at
            .map(|dt| crate::utils::format_local_with_seconds(dt, browser_tz.0)),
        duration,
        recording_path: r_recording_path,
        bytes_sent: r_bytes_sent,
        bytes_received: r_bytes_received,
        commands_count: r_commands_count,
    };

    let base = BaseTemplate::new(
        format!("Play Recording - {}", recording.asset_name),
        user.clone(),
        browser_tz.0,
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
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    // Only admin users (superuser or staff) can view approvals
    if !perms.admin_view {
        return Err(AppError::Authorization(
            "Only administrators can view approvals".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Approvals".to_string(), user.clone(), browser_tz.0)
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
    let items_per_page = 30;

    use crate::schema::users;

    // Resolve the viewer's DB id once so we can:
    //   1. Exclude own pending requests from the main paginated list
    //      (the viewer cannot decide them anyway — separation of
    //      duties is enforced both in `vauban-access` and at the DB
    //      layer via the `approval_separation_of_duties` /
    //      `rejection_separation_of_duties` CHECK constraints).
    //   2. List those own pending requests in a dedicated read-only
    //      block so the operator can still see them at a glance.
    let viewer_uuid = ::uuid::Uuid::parse_str(&auth_user.uuid)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid auth uuid")))?;
    let viewer_db_id: Option<i32> = users::table
        .filter(users::uuid.eq(viewer_uuid))
        .select(users::id)
        .first::<i32>(&mut conn)
        .await
        .optional()
        .map_err(AppError::Database)?;

    // Only show statuses that belong to the approval lifecycle.
    // Sessions that have progressed past approval (connecting, active,
    // terminated, disconnected) are session-state concerns — they
    // belong in the session list, not the approval queue.

    let mut count_query = proxy_sessions::table
        .filter(proxy_sessions::justification.is_not_null())
        .filter(proxy_sessions::status.eq_any(APPROVAL_STATUSES))
        .into_boxed();

    if let Some(ref status) = status_filter {
        count_query = count_query.filter(proxy_sessions::status.eq(status));
    }
    if let Some(id) = viewer_db_id {
        count_query = count_query.filter(proxy_sessions::user_id.ne(id));
    }

    let total_items: i64 = count_query.count().get_result(&mut conn).await.unwrap_or(0);

    let total_pages = ((total_items as f64) / (items_per_page as f64)).ceil() as i32;
    let offset = ((page - 1) * items_per_page) as i64;

    let mut list_query = proxy_sessions::table
        .inner_join(schema_assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::justification.is_not_null())
        .filter(proxy_sessions::status.eq_any(APPROVAL_STATUSES))
        .into_boxed();

    if let Some(ref status) = status_filter {
        list_query = list_query.filter(proxy_sessions::status.eq(status));
    }
    if let Some(id) = viewer_db_id {
        list_query = list_query.filter(proxy_sessions::user_id.ne(id));
    }

    #[allow(clippy::type_complexity)]
    let approvals_data: Vec<(
        uuid::Uuid,
        String,
        String,
        String,
        String,
        Option<String>,
        ipnetwork::IpNetwork,
        chrono::DateTime<chrono::Utc>,
        String,
        Option<i32>,
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
                |(
                    uuid,
                    username,
                    asset_name,
                    asset_type,
                    session_type,
                    justification,
                    client_ip,
                    created_at,
                    status,
                    max_session_duration,
                )| {
                    crate::templates::sessions::approval_list::ApprovalListItem {
                        uuid: uuid.to_string(),
                        username,
                        asset_name,
                        asset_type,
                        session_type,
                        justification,
                        client_ip: client_ip.ip().to_string(),
                        created_at: crate::utils::format_local(created_at, browser_tz.0),
                        status,
                        max_session_duration,
                        is_own: false,
                    }
                },
            )
            .collect();

    // Own pending requests: shown read-only under their own header.
    // We always pull them (no status filter) because a "Rejected"
    // filter on the main list shouldn't hide the operator's still-
    // pending personal requests — they're a separate concern.
    let own_pending: Vec<crate::templates::sessions::approval_list::ApprovalListItem> =
        if let Some(id) = viewer_db_id {
            #[allow(clippy::type_complexity)]
            let rows: Vec<(
                uuid::Uuid,
                String,
                String,
                String,
                String,
                Option<String>,
                ipnetwork::IpNetwork,
                chrono::DateTime<chrono::Utc>,
                String,
                Option<i32>,
            )> = proxy_sessions::table
                .inner_join(schema_assets::table)
                .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
                .filter(proxy_sessions::justification.is_not_null())
                .filter(proxy_sessions::status.eq("pending"))
                .filter(proxy_sessions::user_id.eq(id))
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
                .limit(50)
                .load(&mut conn)
                .await
                .unwrap_or_default();
            rows.into_iter()
                .map(
                    |(
                        uuid,
                        username,
                        asset_name,
                        asset_type,
                        session_type,
                        justification,
                        client_ip,
                        created_at,
                        status,
                        max_session_duration,
                    )| {
                        crate::templates::sessions::approval_list::ApprovalListItem {
                            uuid: uuid.to_string(),
                            username,
                            asset_name,
                            asset_type,
                            session_type,
                            justification,
                            client_ip: client_ip.ip().to_string(),
                            created_at: crate::utils::format_local(created_at, browser_tz.0),
                            status,
                            max_session_duration,
                            is_own: true,
                        }
                    },
                )
                .collect()
        } else {
            Vec::new()
        };

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
        own_pending,
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
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    // Only admin users (superuser or staff) can view approval details
    if !perms.admin_view {
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
        uuid::Uuid,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        ipnetwork::IpNetwork,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        bool,
        Option<i32>,
        ::uuid::Uuid,
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
            proxy_sessions::credential_id,
            proxy_sessions::credential_username,
            proxy_sessions::created_at,
            proxy_sessions::is_recorded,
            proxy_sessions::max_session_duration,
            users::uuid,
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
        a_uuid,
        username,
        user_email,
        asset_name,
        asset_type,
        asset_hostname,
        session_type,
        status,
        justification,
        client_ip,
        credential_id,
        credential_username,
        created_at,
        is_recorded,
        max_session_duration,
        requester_uuid,
    ) = approval_row;

    let is_own = requester_uuid.to_string() == auth_user.uuid;

    // Resolve who approved, rejected or revoked, when, and why.
    type DecisionRow = (
        Option<i32>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<i32>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<i32>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
    );
    let (decided_by, decided_at, decision_reason) = {
        let row: Option<DecisionRow> = proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(approval_uuid))
            .select((
                proxy_sessions::approved_by_id,
                proxy_sessions::approved_at,
                proxy_sessions::rejected_by_id,
                proxy_sessions::rejected_at,
                proxy_sessions::revoked_by_id,
                proxy_sessions::revoked_at,
                proxy_sessions::decision_reason,
            ))
            .first(&mut conn)
            .await
            .ok();

        if let Some((appr_id, appr_at, rej_id, rej_at, rev_id, rev_at, reason)) = row {
            // A revoked grant carries BOTH the original approver and
            // the revoker; the Decision section shows the terminal
            // actor (the revoker) in that case.
            let (actor_id, actor_at) = if status == "revoked" {
                (rev_id.or(appr_id).or(rej_id), rev_at.or(appr_at).or(rej_at))
            } else {
                (appr_id.or(rej_id), appr_at.or(rej_at))
            };

            let actor_name: Option<String> = if let Some(id) = actor_id {
                users::table
                    .filter(users::id.eq(id))
                    .select(users::username)
                    .first(&mut conn)
                    .await
                    .ok()
            } else {
                None
            };

            (
                actor_name,
                actor_at.map(|dt| crate::utils::format_local(dt, browser_tz.0)),
                reason,
            )
        } else {
            (None, None, None)
        }
    };

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
        credential_id,
        credential_username,
        created_at: crate::utils::format_local(created_at, browser_tz.0),
        is_recorded,
        max_session_duration,
        is_own,
        decided_by,
        decided_at,
        decision_reason,
    };

    let flash_messages: Vec<crate::templates::base::FlashMessage> = incoming_flash
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect();

    let base = BaseTemplate::new("Approval Request".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/sessions/approvals")
        .with_messages(flash_messages);
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
    #[serde(
        default,
        deserialize_with = "crate::models::asset::deserialize_optional_i32"
    )]
    pub duration_value: Option<i32>,
    pub duration_unit: Option<String>,
}

impl ApproveForm {
    /// Delegate to the shared resolver in `utils`.
    pub fn resolve_duration_seconds(&self) -> Result<Option<i32>, &'static str> {
        crate::utils::resolve_duration_seconds(self.duration_value, self.duration_unit.as_deref())
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
// allow-ungated: self-service; the caller files an access request for themself (access-rule pipeline decides)
pub async fn submit_access_request(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth_user: WebAuthUser,
    client_addr: crate::middleware::ClientAddr,
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

    // Access rule check — applied uniformly to EVERY user, including
    // superusers and staff. The previous else-branch hardcoded
    // `require_mfa: true, require_approval: true` for privileged users,
    // which was never visible to the rendering layer (`assets.rs` was
    // simultaneously hiding the MFA field for the same user) and produced
    // the visible "MFA code is required (6 digits)" failure when an
    // approval-protected asset was opened by a superuser. All three
    // surfaces (asset_detail, asset_list, submit_access_request) now
    // consult the same `vauban-access` policy.
    let access_result = {
        let result = crate::services::access::can_access_asset(
            &state.access_client,
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
    let trusted = state.config.security.parsed_trusted_proxies();
    let client_ip = crate::middleware::extract_client_ip(&headers, client_addr.addr(), &trusted);

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
        industrial_protocol: None,
        ews_uuid: None,
        tunnel_target_addr: None,
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

    crate::services::emit_audit(
        &state,
        crate::ipc::AuditEvent::new(
            shared::messages::AuditEventType::ApprovalRequested,
            format!(r#"{{"asset":"{}"}}"#, asset.name),
        )
        .user(auth_user.uuid.to_string())
        .session(session_uuid.to_string()),
    );

    // Notify admins via BroadcastService
    let _ = state
        .broadcast
        .send(
            &crate::services::broadcast::WsChannel::Notifications,
            crate::services::broadcast::WsMessage::new(
                "jit-notification",
                format!(
                    r#"{{"type":"access_request","user":"{}","asset":"{}","uuid":"{}"}}"#,
                    auth_user.username, asset.name, session_uuid
                ),
            ),
        )
        .await;

    broadcast_approval_badge(&state).await;

    // Issue #10: queue an email to every active staff/superuser. The
    // pure WebSocket badge is great for live admins, but Vauban does
    // not assume the admin is online -- email is the primary
    // out-of-band channel for "a new access request needs your
    // attention". One row per recipient (UNIQUE(event_id) provides
    // idempotence on a double-submit retry).
    let session_type_str = form.session_type.to_string();
    if let Err(e) = queue_submitted_emails(
        &state,
        session_uuid,
        &auth_user.username,
        &asset.name,
        &session_type_str,
    )
    .await
    {
        tracing::warn!(
            session_uuid = %session_uuid,
            error = %e,
            "Failed to queue access_request.submitted emails (request itself was recorded)"
        );
    }

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

/// Form for an admin reject decision. The optional `reason` is recorded
/// in the audit trail and surfaced to the requester so they understand
/// why their request was denied.
#[derive(Debug, serde::Deserialize)]
pub struct RejectForm {
    pub csrf_token: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Approve an access request.
///
/// POST /sessions/approvals/{uuid}/approve
///
/// SECURITY: this handler is intentionally thin. It validates CSRF,
/// resolves the request context (client IP, user agent, request id)
/// and then delegates the policy check + audit-log insert to
/// `vauban-access` over IPC, in a single Diesel transaction. No
/// SQL UPDATE happens in vauban-web, which would otherwise re-open
/// the door to bypassing the SoD CHECK constraints with a stray
/// `UPDATE proxy_sessions` (Tier-7 structural pin guards against
/// re-introducing one).
#[allow(clippy::too_many_arguments)]
pub async fn approve_access_request(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    extensions: axum::Extension<crate::middleware::audit::RequestId>,
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

    if !perms.admin_view {
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

    let outcome = dispatch_approval_decision(
        &state,
        &auth_user,
        &headers,
        &client_addr,
        &extensions.0,
        &uuid_str,
        shared::messages::ApprovalDecisionKind::Approve,
        duration_override,
        None,
    )
    .await?;

    Ok(approval_outcome_to_response(
        flash,
        &uuid_str,
        outcome,
        "Access request approved",
    ))
}

/// Reject an access request.
///
/// POST /sessions/approvals/{uuid}/reject
#[allow(clippy::too_many_arguments)]
pub async fn reject_access_request(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    extensions: axum::Extension<crate::middleware::audit::RequestId>,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<RejectForm>,
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

    if !perms.admin_view {
        return Err(AppError::Authorization(
            "Only administrators can reject requests".to_string(),
        ));
    }

    let reason = form
        .reason
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let outcome = dispatch_approval_decision(
        &state,
        &auth_user,
        &headers,
        &client_addr,
        &extensions.0,
        &uuid_str,
        shared::messages::ApprovalDecisionKind::Reject,
        None,
        reason,
    )
    .await?;

    Ok(approval_outcome_to_response(
        flash,
        &uuid_str,
        outcome,
        "Access request rejected",
    ))
}

/// Form for an admin revoke decision on an APPROVED grant. The
/// optional `reason` is recorded in the audit trail and surfaced to
/// the requester (WS notification + email).
#[derive(Debug, serde::Deserialize)]
pub struct RevokeForm {
    pub csrf_token: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Form for the post-approval duration update. Unlike `ApproveForm`
/// (where an empty duration means "keep the rule default"), the
/// duration here is MANDATORY: the verb exists only to change it.
#[derive(Debug, serde::Deserialize)]
pub struct UpdateDurationForm {
    pub csrf_token: String,
    #[serde(
        default,
        deserialize_with = "crate::models::asset::deserialize_optional_i32"
    )]
    pub duration_value: Option<i32>,
    pub duration_unit: Option<String>,
}

impl UpdateDurationForm {
    /// Delegate to the shared resolver in `utils`, then require a
    /// value (1 min - 24 h bounds are enforced by the resolver).
    pub fn resolve_required_duration_seconds(&self) -> Result<i32, &'static str> {
        match crate::utils::resolve_duration_seconds(
            self.duration_value,
            self.duration_unit.as_deref(),
        )? {
            Some(secs) => Ok(secs),
            None => Err("A duration is required"),
        }
    }
}

/// `proxy_sessions.status` values that denote a LIVE session (data may
/// be flowing): SSH/RDP handshake or active, IACS waiting for its
/// client or relaying. Used by the revocation cascade and the
/// duration clamp.
const LIVE_SESSION_STATUSES: [&str; 4] =
    ["connecting", "active", "waiting_client", "tunnel_active"];

/// Revoke an APPROVED access grant (instant cut).
///
/// POST /sessions/approvals/{uuid}/revoke
///
/// Defence in depth, three layers:
///   1. The grant row flips to `status = 'revoked'` inside the
///      vauban-access transaction (with the append-only audit row) --
///      NEW sessions are blocked instantly because every connect
///      lookup filters on `status = 'approved'`.
///   2. This handler then cascade-terminates every LIVE session of the
///      (requester, asset) couple through the shared terminate core
///      (SSH/RDP force-close + IACS terminate IPC).
///   3. The WS revalidation probe (`is_proxy_session_live`) backstops
///      any race or dead proxy IPC within `REVALIDATE_INTERVAL_SECS`.
#[allow(clippy::too_many_arguments)]
pub async fn revoke_access_request(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    extensions: axum::Extension<crate::middleware::audit::RequestId>,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<RevokeForm>,
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

    if !perms.admin_view {
        return Err(AppError::Authorization(
            "Only administrators can revoke grants".to_string(),
        ));
    }

    let reason = form
        .reason
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let outcome = dispatch_approval_decision(
        &state,
        &auth_user,
        &headers,
        &client_addr,
        &extensions.0,
        &uuid_str,
        shared::messages::ApprovalDecisionKind::Revoke,
        None,
        reason,
    )
    .await?;

    // Layer 2: the grant is durably `revoked`; now cut every live
    // session of the (requester, asset) couple. Best-effort per
    // session -- layer 3 (WS probe) and the IACS watchdog backstop
    // any failure here.
    if let ApprovalOutcome::Recorded { session_uuid, .. } = &outcome {
        cascade_terminate_grant_sessions(&state, *session_uuid).await;
    }

    Ok(approval_outcome_to_response(
        flash,
        &uuid_str,
        outcome,
        "Access grant revoked; live sessions terminated",
    ))
}

/// Update the duration of an APPROVED access grant.
///
/// POST /sessions/approvals/{uuid}/duration
///
/// `expires_at` is recomputed as `approved_at + duration` (same
/// semantics as the approval itself), in either direction. Live
/// sessions are CLAMPED to the new horizon (never extended: their
/// in-flight max duration stays whatever was fixed at connect time).
/// A duration shortened below the already-elapsed time lands
/// `expires_at` in the past: connects are blocked instantly and the
/// WS probe / cleanup task reap the leftovers.
#[allow(clippy::too_many_arguments)]
pub async fn update_access_duration(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    extensions: axum::Extension<crate::middleware::audit::RequestId>,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<UpdateDurationForm>,
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

    if !perms.admin_view {
        return Err(AppError::Authorization(
            "Only administrators can change grant durations".to_string(),
        ));
    }

    let duration_seconds = match form.resolve_required_duration_seconds() {
        Ok(d) => d,
        Err(msg) => {
            return Ok(flash_redirect(
                flash.error(msg),
                &format!("/sessions/approvals/{}", uuid_str),
            ));
        }
    };

    let outcome = dispatch_approval_decision(
        &state,
        &auth_user,
        &headers,
        &client_addr,
        &extensions.0,
        &uuid_str,
        shared::messages::ApprovalDecisionKind::UpdateDuration,
        Some(duration_seconds),
        None,
    )
    .await?;

    // Clamp live sessions to the new horizon (reduction only).
    if let ApprovalOutcome::Recorded { session_uuid, .. } = &outcome {
        clamp_grant_live_sessions(&state, *session_uuid).await;
    }

    Ok(approval_outcome_to_response(
        flash,
        &uuid_str,
        outcome,
        "Access grant duration updated",
    ))
}

/// Terminate every LIVE proxy session of the (requester, asset) couple
/// of a just-revoked grant. Best-effort: each failure is logged; the
/// WS revalidation probe and the IACS watchdog backstop leftovers.
async fn cascade_terminate_grant_sessions(state: &AppState, grant_uuid: ::uuid::Uuid) {
    use crate::models::session::ProxySession;

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                grant_uuid = %grant_uuid,
                error = %e,
                "revoke cascade: DB pool unavailable; WS probe will backstop"
            );
            return;
        }
    };

    let grant: Option<(i32, i32)> = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(grant_uuid))
        .select((proxy_sessions::user_id, proxy_sessions::asset_id))
        .first(&mut conn)
        .await
        .ok();
    let Some((grant_user_id, grant_asset_id)) = grant else {
        return;
    };

    let live_sessions: Vec<ProxySession> = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(grant_user_id))
        .filter(proxy_sessions::asset_id.eq(grant_asset_id))
        .filter(proxy_sessions::status.eq_any(LIVE_SESSION_STATUSES))
        .load(&mut conn)
        .await
        .unwrap_or_default();
    drop(conn);

    for session in &live_sessions {
        if let Err(e) = crate::services::session_termination::terminate_live_session(
            state,
            session,
            "access_revoked",
        )
        .await
        {
            tracing::warn!(
                grant_uuid = %grant_uuid,
                session_uuid = %session.uuid,
                error = %e,
                "revoke cascade: failed to terminate live session; WS probe will backstop"
            );
        }
    }

    if !live_sessions.is_empty() {
        tracing::info!(
            grant_uuid = %grant_uuid,
            terminated = live_sessions.len(),
            "revoke cascade: live sessions terminated"
        );
        crate::services::session_termination::broadcast_session_list_updates(state).await;
    }
}

/// Clamp `expires_at` of every LIVE session of the grant's
/// (requester, asset) couple to the grant's new horizon. NULL
/// `expires_at` counts as "unbounded" and is clamped too; later
/// horizons are reduced; earlier ones are left as-is (a duration
/// update NEVER extends an in-flight session).
async fn clamp_grant_live_sessions(state: &AppState, grant_uuid: ::uuid::Uuid) {
    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                grant_uuid = %grant_uuid,
                error = %e,
                "duration clamp: DB pool unavailable; WS probe will backstop"
            );
            return;
        }
    };

    type GrantRow = (i32, i32, Option<chrono::DateTime<chrono::Utc>>);
    let grant: Option<GrantRow> = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(grant_uuid))
        .select((
            proxy_sessions::user_id,
            proxy_sessions::asset_id,
            proxy_sessions::expires_at,
        ))
        .first(&mut conn)
        .await
        .ok();
    let Some((grant_user_id, grant_asset_id, Some(new_horizon))) = grant else {
        return;
    };

    let clamped = diesel::update(
        proxy_sessions::table
            .filter(proxy_sessions::user_id.eq(grant_user_id))
            .filter(proxy_sessions::asset_id.eq(grant_asset_id))
            .filter(proxy_sessions::status.eq_any(LIVE_SESSION_STATUSES))
            .filter(
                proxy_sessions::expires_at
                    .is_null()
                    .or(proxy_sessions::expires_at.gt(new_horizon)),
            ),
    )
    .set((
        proxy_sessions::expires_at.eq(Some(new_horizon)),
        proxy_sessions::updated_at.eq(chrono::Utc::now()),
    ))
    .execute(&mut conn)
    .await
    .unwrap_or(0);

    if clamped > 0 {
        tracing::info!(
            grant_uuid = %grant_uuid,
            clamped = clamped,
            new_horizon = %new_horizon,
            "duration update: live sessions clamped to the new horizon"
        );
    }
}

/// Outcome from `dispatch_approval_decision`, returned to keep the
/// HTTP-shape mapping in a single place (`approval_outcome_to_response`).
///
/// Fields on `Recorded` are kept even when unread by the response
/// mapper -- Tier-3 tests assert against them via `match` arms, and
/// the structured info is also useful when a future caller wants to
/// surface the audit-log id back to the user.
#[allow(dead_code)]
enum ApprovalOutcome {
    Recorded {
        audit_log_id: i64,
        requester_id: Option<i32>,
        session_uuid: ::uuid::Uuid,
        decision: shared::messages::ApprovalDecisionKind,
    },
    Denied(shared::messages::ApprovalDenyReason),
}

/// Common path for approve/reject:
///   1. Resolve trusted-proxy client IP, user agent, request id.
///   2. Send `RecordApprovalDecision` over IPC.
///   3. On success, push WS notifications and the badge OOB swap.
///
/// Centralised so a future `cancel`-by-admin or `expire`-by-admin verb
/// reuses the exact same audit semantics. The thin web handlers stay
/// HTTP-focused (CSRF, RBAC, form parsing, redirect).
#[allow(clippy::too_many_arguments)]
async fn dispatch_approval_decision(
    state: &AppState,
    auth_user: &WebAuthUser,
    headers: &axum::http::HeaderMap,
    client_addr: &crate::middleware::ClientAddr,
    request_id: &crate::middleware::audit::RequestId,
    uuid_str: &str,
    decision: shared::messages::ApprovalDecisionKind,
    duration_override_seconds: Option<i32>,
    decision_reason: Option<String>,
) -> AppResult<ApprovalOutcome> {
    let session_uuid = ::uuid::Uuid::parse_str(uuid_str)
        .map_err(|_| AppError::Validation("Invalid request identifier".to_string()))?;

    let trusted = state.config.security.parsed_trusted_proxies();
    let resolved_ip =
        crate::middleware::resolve_client_ip(headers, client_addr.addr().ip(), &trusted);

    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Stash a copy of the decision reason for the post-success email
    // hook (the IPC call below moves the original).
    let decision_reason_clone = decision_reason.clone();

    let outcome = state
        .access_client
        .record_approval_decision(
            &auth_user.uuid,
            uuid_str,
            decision,
            duration_override_seconds,
            decision_reason,
            Some(resolved_ip.to_string()),
            user_agent,
            Some(request_id.0.clone()),
        )
        .await?;

    match outcome {
        Ok(audit_log_id) => {
            // Resolve the requester for the WS notification (best-effort,
            // does not block the response).
            let requester_id = if let Ok(mut conn) = state.db_pool.get().await {
                proxy_sessions::table
                    .filter(proxy_sessions::uuid.eq(session_uuid))
                    .select(proxy_sessions::user_id)
                    .first::<i32>(&mut conn)
                    .await
                    .ok()
            } else {
                None
            };

            // Notify the requester. Failure here is non-fatal -- the audit
            // row is already durable.
            if let Some(uid) = requester_id
                && let Ok(mut conn) = state.db_pool.get().await
                && let Ok(req_uuid) = crate::schema::users::table
                    .filter(crate::schema::users::id.eq(uid))
                    .select(crate::schema::users::uuid)
                    .first::<::uuid::Uuid>(&mut conn)
                    .await
            {
                let kind_str = match decision {
                    shared::messages::ApprovalDecisionKind::Approve => "request_approved",
                    shared::messages::ApprovalDecisionKind::Reject => "request_rejected",
                    shared::messages::ApprovalDecisionKind::Revoke => "request_revoked",
                    shared::messages::ApprovalDecisionKind::UpdateDuration => {
                        "request_duration_updated"
                    }
                };
                let _ = state
                    .broadcast
                    .send(
                        &crate::services::broadcast::WsChannel::Notifications,
                        crate::services::broadcast::WsMessage::new(
                            "jit-notification",
                            format!(
                                r#"{{"type":"{}","session_uuid":"{}","user_uuid":"{}"}}"#,
                                kind_str, session_uuid, req_uuid
                            ),
                        ),
                    )
                    .await;
            }

            broadcast_approval_badge(state).await;

            tracing::info!(
                session_uuid = %session_uuid,
                actor = %auth_user.username,
                decision = ?decision,
                audit_log_id,
                "JIT access request decision recorded via IPC"
            );

            // Audit: an approval grants privileged access -> escalation.
            // The decision is already durable on the access side, so a
            // failed critical emit is logged (we cannot un-grant), but the
            // WORM record is still attempted with delivery confirmation.
            let (ev, label) = match decision {
                shared::messages::ApprovalDecisionKind::Approve => {
                    (shared::messages::AuditEventType::ApprovalGranted, "granted")
                }
                shared::messages::ApprovalDecisionKind::Reject => {
                    (shared::messages::AuditEventType::ApprovalDenied, "denied")
                }
                shared::messages::ApprovalDecisionKind::Revoke => {
                    (shared::messages::AuditEventType::ApprovalRevoked, "revoked")
                }
                shared::messages::ApprovalDecisionKind::UpdateDuration => (
                    shared::messages::AuditEventType::ApprovalDurationUpdated,
                    "duration_updated",
                ),
            };
            if let Err(e) = crate::services::emit_audit_critical(
                state,
                crate::ipc::AuditEvent::new(ev, format!(r#"{{"decision":"{label}"}}"#))
                    .user(auth_user.uuid.clone())
                    .session(session_uuid.to_string())
                    .ip(Some(resolved_ip)),
            )
            .await
            {
                tracing::error!(error = %e, "approval decision: critical audit emit failed");
            }

            // Email the requester (Issue #10). Best-effort: a failure
            // here is logged but never bubbles up -- the audit row is
            // already durable on the access-side, so the user has
            // learned the outcome from the WS notification anyway.
            // No email for update-duration (WS notification only): the
            // grant stays live, so there is no actionable outcome to
            // notify out-of-band.
            let email_worthy = !matches!(
                decision,
                shared::messages::ApprovalDecisionKind::UpdateDuration
            );
            if email_worthy
                && let Some(uid) = requester_id
                && let Err(e) = queue_approval_email(
                    state,
                    uid,
                    session_uuid,
                    decision,
                    &auth_user.username,
                    decision_reason_clone.as_deref(),
                )
                .await
            {
                tracing::warn!(
                    session_uuid = %session_uuid,
                    decision = ?decision,
                    error = %e,
                    "Failed to queue approval-decision email \
                     (audit log already recorded; admin can resend)"
                );
            }

            Ok(ApprovalOutcome::Recorded {
                audit_log_id,
                requester_id,
                session_uuid,
                decision,
            })
        }
        Err(reason) => {
            tracing::info!(
                session_uuid = %session_uuid,
                actor = %auth_user.username,
                decision = ?decision,
                deny_reason = ?reason,
                "JIT access request decision denied (separation of duties / state)"
            );
            Ok(ApprovalOutcome::Denied(reason))
        }
    }
}

/// Queue one `access_request.submitted` email per active superuser (Issue #10).
///
/// "Active superuser" is the canonical approver pool today. A future
/// access-rule-driven approver routing can replace this lookup without
/// touching the call sites.
///
/// Best-effort: any failure here is logged and never propagated -- the
/// access request itself is durable, and the WebSocket fan-out has
/// already alerted any live admin.
async fn queue_submitted_emails(
    state: &AppState,
    session_uuid: ::uuid::Uuid,
    requester_username: &str,
    asset_name: &str,
    protocol: &str,
) -> Result<(), String> {
    use crate::schema::users;
    use crate::services::mailer::{
        AccessRequestSubmittedEvent, EmailEvent, EmailRecipient, deterministic_event_id,
    };

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    let approver_emails: Vec<(String, String)> = users::table
        .filter(users::is_active.eq(true))
        .filter(users::is_superuser.eq(true))
        .filter(users::email.ne(""))
        .select((users::email, users::username))
        .load(&mut conn)
        .await
        .map_err(|e| format!("approver lookup: {}", e))?;
    drop(conn);

    if approver_emails.is_empty() {
        return Ok(());
    }

    let approval_url = format!(
        "{}/sessions/approvals/{}",
        state.config.mailer.base_url, session_uuid
    );
    let business_key = format!("submitted:{}", session_uuid);

    let mut errors: Vec<String> = Vec::new();
    for (email, username) in approver_emails {
        let event_id = deterministic_event_id("access_request.submitted", &business_key, &email);
        let event = EmailEvent::AccessRequestSubmitted(AccessRequestSubmittedEvent {
            event_id,
            recipient: EmailRecipient::new(email, username),
            requester_username: requester_username.to_string(),
            asset_name: asset_name.to_string(),
            protocol: protocol.to_string(),
            justification: None,
            approval_url: approval_url.clone(),
            base_url: state.config.mailer.base_url.clone(),
            from_brand: state.config.mailer.from_name.clone(),
        });
        let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
        match state.mailer.queue(&mut conn, &event).await {
            Ok(()) | Err(crate::services::mailer::MailerError::Duplicate) => {}
            Err(e) => errors.push(e.to_string()),
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Queue an approval-decision email to the request author (Issue #10).
///
/// Best-effort: any error here is logged by the caller and never
/// propagates -- the audit log is the source of truth for "decision
/// taken", and the WebSocket notification has already informed the
/// user. The email is a courtesy duplicate.
///
/// The function loads (requester email, asset name, protocol) and
/// builds the matching `EmailEvent`. Multiple DB lookups are merged
/// into a single connection borrow to keep the pool occupancy low.
async fn queue_approval_email(
    state: &AppState,
    requester_id: i32,
    session_uuid: ::uuid::Uuid,
    decision: shared::messages::ApprovalDecisionKind,
    approver_username: &str,
    rejection_reason: Option<&str>,
) -> Result<(), String> {
    use crate::schema::{assets, proxy_sessions, users};
    use crate::services::mailer::{
        AccessRequestApprovedEvent, AccessRequestRejectedEvent, AccessRequestRevokedEvent,
        EmailEvent, EmailRecipient, deterministic_event_id,
    };

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;

    // Requester contact details.
    let (req_email, _req_username): (String, String) = users::table
        .filter(users::id.eq(requester_id))
        .select((users::email, users::username))
        .first(&mut conn)
        .await
        .map_err(|e| format!("requester lookup: {}", e))?;
    if req_email.is_empty() {
        // No address on file -> nothing to do. Non-error.
        return Ok(());
    }

    // Asset metadata for the email body.
    let (asset_name, protocol): (String, String) = proxy_sessions::table
        .inner_join(assets::table.on(assets::id.eq(proxy_sessions::asset_id)))
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .select((assets::name, proxy_sessions::session_type))
        .first(&mut conn)
        .await
        .map_err(|e| format!("session lookup: {}", e))?;
    drop(conn);

    let recipient = EmailRecipient::bare(&req_email);
    let business_key = format!("{}:{:?}", session_uuid, decision);
    let event_id = deterministic_event_id(decision_kind_str(decision), &business_key, &req_email);

    let event = match decision {
        shared::messages::ApprovalDecisionKind::Approve => {
            EmailEvent::AccessRequestApproved(AccessRequestApprovedEvent {
                event_id,
                recipient,
                asset_name,
                protocol,
                approver_username: approver_username.to_string(),
                session_url: format!(
                    "{}/sessions/approvals/{}",
                    state.config.mailer.base_url, session_uuid
                ),
                valid_until: None,
                base_url: state.config.mailer.base_url.clone(),
                from_brand: state.config.mailer.from_name.clone(),
            })
        }
        shared::messages::ApprovalDecisionKind::Reject => {
            EmailEvent::AccessRequestRejected(AccessRequestRejectedEvent {
                event_id,
                recipient,
                asset_name,
                protocol,
                approver_username: approver_username.to_string(),
                reason: rejection_reason.map(str::to_string),
                base_url: state.config.mailer.base_url.clone(),
                from_brand: state.config.mailer.from_name.clone(),
            })
        }
        shared::messages::ApprovalDecisionKind::Revoke => {
            EmailEvent::AccessRequestRevoked(AccessRequestRevokedEvent {
                event_id,
                recipient,
                asset_name,
                protocol,
                approver_username: approver_username.to_string(),
                reason: rejection_reason.map(str::to_string),
                base_url: state.config.mailer.base_url.clone(),
                from_brand: state.config.mailer.from_name.clone(),
            })
        }
        // No email for update-duration; the caller filters this out
        // (`email_worthy`), kept as a no-op for exhaustiveness.
        shared::messages::ApprovalDecisionKind::UpdateDuration => return Ok(()),
    };

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    match state.mailer.queue(&mut conn, &event).await {
        Ok(()) => Ok(()),
        Err(crate::services::mailer::MailerError::Duplicate) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

fn decision_kind_str(decision: shared::messages::ApprovalDecisionKind) -> &'static str {
    match decision {
        shared::messages::ApprovalDecisionKind::Approve => "access_request.approved",
        shared::messages::ApprovalDecisionKind::Reject => "access_request.rejected",
        shared::messages::ApprovalDecisionKind::Revoke => "access_request.revoked",
        shared::messages::ApprovalDecisionKind::UpdateDuration => "access_request.duration_updated",
    }
}

fn approval_outcome_to_response(
    flash: crate::middleware::flash::Flash,
    uuid_str: &str,
    outcome: ApprovalOutcome,
    success_message: &str,
) -> Response {
    let detail_url = format!("/sessions/approvals/{}", uuid_str);
    match outcome {
        ApprovalOutcome::Recorded { .. } => {
            flash_redirect(flash.success(success_message), &detail_url)
        }
        ApprovalOutcome::Denied(reason) => {
            flash_redirect(flash.error(reason.as_message()), &detail_url)
        }
    }
}

/// Broadcast an OOB update for the sidebar approval badge.
///
/// Queries the current pending approval count and sends it as an HTMX
/// out-of-band swap targeting `#sidebar-approval-badge`. Non-admin pages
/// ignore this because the target element does not exist in their DOM.
async fn broadcast_approval_badge(state: &AppState) {
    if let Ok(mut conn) = state.db_pool.get().await {
        let count: i64 = proxy_sessions::table
            .filter(proxy_sessions::status.eq("pending"))
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);

        let badge_html = if count > 0 {
            format!(
                r#"<span id="sidebar-approval-badge" hx-swap-oob="outerHTML" class="ml-auto inline-flex items-center rounded-full bg-vauban-600 px-2 py-0.5 text-xs font-medium text-white">{}</span>"#,
                count
            )
        } else {
            r#"<span id="sidebar-approval-badge" hx-swap-oob="outerHTML"></span>"#.to_string()
        };

        let _ = state.broadcast.send_raw("notifications", badge_html).await;
    }
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
// allow-ungated: self-service; ownership of the request is checked in the body
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

    crate::services::emit_audit(
        &state,
        crate::ipc::AuditEvent::new(shared::messages::AuditEventType::ApprovalCancelled, "{}")
            .user(auth_user.uuid.to_string())
            .session(session_uuid.to_string()),
    );

    let _ = state
        .broadcast
        .send(
            &crate::services::broadcast::WsChannel::Notifications,
            crate::services::broadcast::WsMessage::new(
                "jit-notification",
                format!(
                    r#"{{"type":"request_cancelled","session_uuid":"{}","user_uuid":"{}"}}"#,
                    session_uuid, auth_user.uuid
                ),
            ),
        )
        .await;

    broadcast_approval_badge(&state).await;

    Ok(Redirect::to("/sessions/my-requests").into_response())
}

/// My access requests page (user self-service).
///
/// GET /sessions/my-requests
const MY_REQUESTS_PER_PAGE: i64 = 30;

pub async fn my_requests(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    jar: CookieJar,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("My Requests".to_string(), user.clone(), browser_tz.0)
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

    let page: i32 = params
        .get("page")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1)
        .max(1);

    let statuses = [
        "pending",
        "approved",
        "rejected",
        "revoked",
        "expired",
        "consumed",
        "active",
        "disconnected",
        "terminated",
    ];

    let total_items: i64 = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::justification.is_not_null())
        .filter(proxy_sessions::status.eq_any(&statuses))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);

    let total_pages = ((total_items as f64) / (MY_REQUESTS_PER_PAGE as f64))
        .ceil()
        .max(1.0) as i32;
    let page = page.min(total_pages);
    let offset = ((page - 1) as i64) * MY_REQUESTS_PER_PAGE;

    #[allow(clippy::type_complexity)]
    let requests_data: Vec<(
        uuid::Uuid,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<i32>,
    )> = proxy_sessions::table
        .inner_join(schema_assets::table)
        .left_join(users::table.on(users::id.nullable().eq(proxy_sessions::approved_by_id)))
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::justification.is_not_null())
        .filter(proxy_sessions::status.eq_any(&statuses))
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
        .limit(MY_REQUESTS_PER_PAGE)
        .offset(offset)
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let requests: Vec<crate::templates::sessions::my_requests::MyRequestItem> = requests_data
        .into_iter()
        .map(
            |(
                uuid,
                asset_name,
                asset_hostname,
                asset_type,
                session_type,
                status,
                justification,
                created_at,
                approved_at,
                approved_by,
                max_session_duration,
            )| {
                crate::templates::sessions::my_requests::MyRequestItem {
                    uuid: uuid.to_string(),
                    asset_name,
                    asset_hostname,
                    asset_type,
                    session_type,
                    status,
                    justification,
                    created_at: crate::utils::format_local(created_at, browser_tz.0),
                    approved_at: approved_at.map(|dt| crate::utils::format_local(dt, browser_tz.0)),
                    approved_by,
                    max_session_duration,
                }
            },
        )
        .collect();

    use crate::templates::accounts::user_list::Pagination;

    let start_index = if total_items > 0 { offset + 1 } else { 0 };
    let end_index = (offset + MY_REQUESTS_PER_PAGE).min(total_items);

    let pagination = if total_items > 0 {
        Some(Pagination {
            current_page: page,
            total_pages,
            total_items: total_items as i32,
            items_per_page: MY_REQUESTS_PER_PAGE as i32,
            has_previous: page > 1,
            has_next: page < total_pages,
            start_index: start_index as i32,
            end_index: end_index as i32,
        })
    } else {
        None
    };

    // IACS / EWS section integration (palier 6).
    //
    // The kill-switch is encoded in `perms.iacs_read` (the
    // permission_context_middleware forces it to `false` when
    // `[industrial].enabled = false`), so a single boolean
    // collapses both the Casbin and the kill-switch decisions.
    let iacs_visible = perms.iacs_read;
    let iacs_request_allowed = perms.iacs_request;
    let ews_items = if iacs_visible {
        crate::handlers::web::iacs::load_my_ews_items(&state, user_id, browser_tz.0)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "load_my_ews_items failed; rendering empty");
                Vec::new()
            })
    } else {
        Vec::new()
    };
    let csrf_token_for_forms = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let template = crate::templates::sessions::my_requests::MyRequestsTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        requests,
        pagination,
        iacs_visible,
        iacs_request_allowed,
        ews_items,
        csrf_token: csrf_token_for_forms,
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
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    // Only admin users (superuser or staff) can view active sessions
    if !perms.admin_view {
        return Err(AppError::Authorization(
            "Only administrators can view active sessions".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Active Sessions".to_string(), user.clone(), browser_tz.0)
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

    const ACTIVE_PER_PAGE: i64 = 30;

    let page: i32 = params
        .get("page")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1)
        .max(1);

    // ACTIVE-LIST FILTER (kept in lock-step across three call sites:
    // here, `tasks::dashboard::fetch_active_sessions_full`, and
    // `handlers::websocket::fetch_active_sessions_list`).
    //
    // SSH/RDP sessions live in `status = 'active'`. IACS tunnels live
    // in `status = 'tunnel_active'` (the "EWS handshake done, bytes
    // forwarding" leg of the IACS state machine -- see
    // `models::session::SessionStatus`). The admin "Active Sessions"
    // page MUST surface BOTH so an operator gets a single pane on
    // every live protocol; the per-session WS push from
    // `vauban-proxy-iacs` (`Message::IacsTunnelStatusUpdate`) flips
    // the row to `tunnel_active` + sets `connected_at` so the second
    // filter clause keeps the same semantics ("really connected").
    // Pinned by
    // `tests::active_list_query_includes_iacs_tunnel_active_status`.
    //
    // Industrial kill-switch (layer 2): when `industrial.enabled =
    // false`, IACS tunnels are excluded from the operational
    // `/sessions/active` pane (`session_type.ne(IacsTunnel)`). The
    // base `status.eq_any(["active", "tunnel_active"])` clause is
    // preserved so the three-site lock-step pin stays exact; the
    // extra exclusion simply removes the IACS leg under the switch.
    let mut total_query = proxy_sessions::table
        .inner_join(schema_assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::status.eq_any(["active", "tunnel_active"]))
        .filter(proxy_sessions::connected_at.is_not_null())
        .into_boxed();
    if !state.config.industrial.enabled {
        total_query = total_query.filter(proxy_sessions::session_type.ne(SessionType::IacsTunnel));
    }
    let total_items: i64 = total_query.count().get_result(&mut conn).await.unwrap_or(0);

    let total_pages = ((total_items as f64) / (ACTIVE_PER_PAGE as f64))
        .ceil()
        .max(1.0) as i32;
    let page = page.min(total_pages);
    let offset = ((page - 1) as i64) * ACTIVE_PER_PAGE;

    let mut data_query = proxy_sessions::table
        .inner_join(schema_assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::status.eq_any(["active", "tunnel_active"]))
        .filter(proxy_sessions::connected_at.is_not_null())
        .into_boxed();
    // Industrial kill-switch (layer 2): same exclusion as the count
    // query above so pagination stays in lock-step.
    if !state.config.industrial.enabled {
        data_query = data_query.filter(proxy_sessions::session_type.ne(SessionType::IacsTunnel));
    }

    #[allow(clippy::type_complexity)]
    let sessions_data: Vec<(
        i32,
        uuid::Uuid,
        String,
        String,
        String,
        String,
        ipnetwork::IpNetwork,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = data_query
        .select((
            proxy_sessions::id,
            proxy_sessions::uuid,
            users::username,
            schema_assets::name,
            schema_assets::hostname,
            proxy_sessions::session_type,
            proxy_sessions::client_ip,
            proxy_sessions::connected_at,
        ))
        .order(proxy_sessions::connected_at.desc())
        .limit(ACTIVE_PER_PAGE)
        .offset(offset)
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let sessions: Vec<crate::templates::sessions::active_list::ActiveSessionItem> = sessions_data
        .into_iter()
        .filter_map(
            |(
                session_id,
                uuid,
                username,
                asset_name,
                asset_hostname,
                session_type,
                client_ip,
                connected_at,
            )| {
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
                    id: session_id,
                    uuid: uuid.to_string(),
                    username,
                    asset_name,
                    asset_hostname,
                    session_type,
                    client_ip: client_ip.ip().to_string(),
                    connected_at: connected,
                    duration: duration_str,
                })
            },
        )
        .collect();

    use crate::templates::accounts::user_list::Pagination as ActPagination;

    let start_index = if total_items > 0 { offset + 1 } else { 0 };
    let end_index = (offset + ACTIVE_PER_PAGE).min(total_items);

    let pagination = if total_items > 0 {
        Some(ActPagination {
            current_page: page,
            total_pages,
            total_items: total_items as i32,
            items_per_page: ACTIVE_PER_PAGE as i32,
            has_previous: page > 1,
            has_next: page < total_pages,
            start_index: start_index as i32,
            end_index: end_index as i32,
        })
    } else {
        None
    };

    let template = ActiveListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        sessions,
        pagination,
        industrial_enabled: state.config.industrial.enabled,
        tz: browser_tz.0,
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
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    headers: axum::http::HeaderMap,
    axum::extract::Path(session_uuid_str): axum::extract::Path<String>,
) -> Result<axum::response::Response, AppError> {
    use axum::body::Body;
    use axum::http::{StatusCode, header};
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    use tokio_util::io::ReaderStream;

    if !perms.admin_view {
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

/// Recording-centric detail page (issue #29 / UX-28).
///
/// Reachable from the recordings list as the renamed "Recording
/// Details" button. Replaces the misleading "View" link that jumped
/// to a session-centric page and broke the sidebar breadcrumb (the
/// `is_recordings` flag in [`crate::templates::base`] only matches
/// when the URL contains `/recordings`).
///
/// Authorization layers:
/// - Casbin `admin_view` -- functional capability (same family as
///   the rest of the recording handlers).
/// - Anti-enumeration: any 404-class denial collapses to the same
///   generic 404 (Axum's `Path<Uuid>` extractor returns 400 on a
///   malformed UUID, which is fine since "this is not even a UUID
///   shape" is not a useful enumeration signal).
/// - This is a *post-mortem* read of an immutable artefact, not a
///   live-session viewer, so the `services::session_access::verify`
///   seam (which gates running sessions) does not apply.
//
// allow-uuid-lookup: post-mortem recording artefact, not a live session
// viewer. The session_access seam scopes to live sessions only.
pub async fn recording_detail(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    axum::extract::Path(session_uuid): axum::extract::Path<::uuid::Uuid>,
) -> Result<axum::response::Response, AppError> {
    use crate::templates::sessions::recording_detail::{
        ApprovalNarrative, IntegrityViewModel, RecordingDetailViewModel, format_bytes_human,
        format_duration_human, format_label, status_pill, truncate_blake3,
    };

    if !perms.admin_view {
        return Err(AppError::NotFound("Not found".to_string()));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    use crate::schema::users;

    // SELECT the session row + asset name/hostname + requester username.
    // Approver and rejecter are looked up in two follow-up queries to
    // keep the join shape simple (Diesel does not support the same
    // table joined three times via the DSL without explicit aliases).
    #[allow(clippy::type_complexity)]
    let row: (
        i32,
        ::uuid::Uuid,
        SessionType,
        String,
        ipnetwork::IpNetwork,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<i32>,
        Option<String>,
        Option<i16>,
        Option<i16>,
        Option<i32>,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<i32>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<i32>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        String,
        String,
        String,
    ) = match proxy_sessions::table
        .inner_join(schema_assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .filter(proxy_sessions::is_recorded.eq(true))
        .filter(proxy_sessions::recording_path.is_not_null())
        .select((
            proxy_sessions::id,
            proxy_sessions::uuid,
            proxy_sessions::session_type,
            proxy_sessions::status,
            proxy_sessions::client_ip,
            proxy_sessions::credential_username,
            proxy_sessions::connected_at,
            proxy_sessions::disconnected_at,
            proxy_sessions::justification,
            proxy_sessions::recording_blake3,
            proxy_sessions::recording_size_bytes,
            proxy_sessions::recording_duration_ms,
            proxy_sessions::recording_event_count,
            proxy_sessions::recording_format,
            proxy_sessions::recording_width,
            proxy_sessions::recording_height,
            proxy_sessions::recording_segment_count,
            proxy_sessions::recording_codec,
            proxy_sessions::recording_finalized_at,
            proxy_sessions::approved_by_id,
            proxy_sessions::approved_at,
            proxy_sessions::rejected_by_id,
            proxy_sessions::rejected_at,
            proxy_sessions::decision_reason,
            users::username,
            schema_assets::name,
            schema_assets::hostname,
        ))
        .first(&mut conn)
        .await
    {
        Ok(r) => r,
        // Anti-enumeration: every "not found"/"not recorded"/"path
        // missing" case collapses to the same generic 404.
        Err(_) => return Err(AppError::NotFound("Not found".to_string())),
    };

    let (
        session_id,
        s_uuid,
        s_type,
        s_status,
        s_client_ip,
        s_cred_username,
        s_connected_at,
        s_disconnected_at,
        s_justification,
        s_blake3,
        s_size_bytes,
        s_duration_ms,
        s_event_count,
        s_format,
        s_width,
        s_height,
        s_segment_count,
        s_codec,
        s_finalized_at,
        s_approved_by_id,
        s_approved_at,
        s_rejected_by_id,
        s_rejected_at,
        s_decision_reason,
        requester_username,
        asset_name,
        asset_hostname,
    ) = row;

    // Resolve approver / rejecter usernames if present.
    let approver_username: Option<String> = if let Some(id) = s_approved_by_id {
        users::table
            .filter(users::id.eq(id))
            .select(users::username)
            .first::<String>(&mut conn)
            .await
            .ok()
    } else {
        None
    };
    let rejecter_username: Option<String> = if let Some(id) = s_rejected_by_id {
        users::table
            .filter(users::id.eq(id))
            .select(users::username)
            .first::<String>(&mut conn)
            .await
            .ok()
    } else {
        None
    };

    let session_type_label = match s_type {
        SessionType::Ssh => "SSH (port 22)",
        SessionType::Rdp => "RDP (port 3389)",
        SessionType::IacsTunnel => "IACS tunnel",
    };

    let (status_label, status_pill_class) = status_pill(&s_status);

    let duration_human = match (s_connected_at, s_disconnected_at) {
        (Some(start), Some(end)) => {
            let ms = (end - start).num_milliseconds().max(0);
            Some(format_duration_human(ms))
        }
        _ => None,
    };

    let approval = match (
        approver_username.clone(),
        s_approved_at,
        rejecter_username.clone(),
        s_rejected_at,
    ) {
        (Some(au), Some(at), _, _) => ApprovalNarrative::Approved {
            approver_username: au,
            approved_at_utc: crate::utils::format_local_with_seconds(at, browser_tz.0),
        },
        (_, _, Some(ru), Some(rt)) => ApprovalNarrative::Rejected {
            rejecter_username: ru,
            rejected_at_utc: crate::utils::format_local_with_seconds(rt, browser_tz.0),
            reason: s_decision_reason.clone(),
        },
        _ => ApprovalNarrative::Awaiting,
    };

    let approver_line = if let (Some(au), Some(at)) = (approver_username, s_approved_at) {
        Some(format!(
            "{} at {}",
            au,
            crate::utils::format_local_with_seconds(at, browser_tz.0)
        ))
    } else {
        None
    };
    let rejecter_line = if let (Some(ru), Some(rt)) = (rejecter_username, s_rejected_at) {
        Some(format!(
            "{} at {}",
            ru,
            crate::utils::format_local_with_seconds(rt, browser_tz.0)
        ))
    } else {
        None
    };
    let rejection_reason = if rejecter_line.is_some() {
        s_decision_reason.clone()
    } else {
        None
    };

    // Integrity bundle: present only when the hydrator has finalized
    // the row. `corrupt_integrity` is true when finalized but the
    // format column is NULL (the hydrator's marker for an unparseable
    // meta.json).
    let (integrity, corrupt_integrity) = if let Some(blake3_hex) = s_blake3 {
        let format = s_format.clone().unwrap_or_default();
        let format_label_str = format_label(&format).to_string();
        let blake3_truncated = truncate_blake3(&blake3_hex);
        let size_human = s_size_bytes.map(format_bytes_human).unwrap_or_default();
        let dur_human = s_duration_ms.map(format_duration_human).unwrap_or_default();
        let finalized_at_utc = s_finalized_at
            .map(|dt| crate::utils::format_local_with_seconds(dt, browser_tz.0))
            .unwrap_or_default();
        let bundle = IntegrityViewModel {
            blake3_hex,
            blake3_truncated,
            size_human,
            duration_human: dur_human,
            format,
            format_label: format_label_str,
            width: s_width.unwrap_or(0),
            height: s_height.unwrap_or(0),
            event_count: s_event_count,
            segment_count: s_segment_count,
            codec: s_codec,
            finalized_at_utc,
        };
        (Some(bundle), false)
    } else if s_finalized_at.is_some() {
        // Finalized but no blake3 -> hydrator marked corrupt.
        (None, true)
    } else {
        (None, false)
    };

    let session_uuid_str = s_uuid.to_string();
    let recording_vm = RecordingDetailViewModel {
        session_uuid: session_uuid_str.clone(),
        session_id,
        session_type: s_type.to_string(),
        session_type_label: session_type_label.to_string(),
        status: s_status.clone(),
        status_label: status_label.to_string(),
        status_pill_class: status_pill_class.to_string(),
        asset_name: asset_name.clone(),
        asset_hostname,
        source_ip: s_client_ip.ip().to_string(),
        credential_username: crate::templates::sessions::recording_detail::credential_display(
            &s_cred_username,
            &s_type.to_string(),
        ),
        requester_username,
        connected_at_utc: s_connected_at
            .map(|dt| crate::utils::format_local_with_seconds(dt, browser_tz.0)),
        disconnected_at_utc: s_disconnected_at
            .map(|dt| crate::utils::format_local_with_seconds(dt, browser_tz.0)),
        duration_human,
        justification: s_justification,
        approval,
        approver_line,
        rejecter_line,
        rejection_reason,
        integrity,
        corrupt_integrity,
        play_url: format!("/sessions/recordings/{}/play", session_id),
        download_url: format!("/sessions/recordings/{}/download", session_uuid_str),
        back_url: "/sessions/recordings".to_string(),
        list_url: "/sessions/recordings".to_string(),
        show_play_recording: s_type != SessionType::IacsTunnel,
        show_inspect_capture: s_type == SessionType::IacsTunnel,
        inspect_url: if s_type == SessionType::IacsTunnel {
            format!("/sessions/recordings/{}/inspect", session_uuid_str)
        } else {
            String::new()
        },
    };

    let base = BaseTemplate::new(
        format!("Recording Details - {}", asset_name),
        user.clone(),
        browser_tz.0,
    )
    .with_current_path("/sessions/recordings");
    let perms_for_template = perms.clone();
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = RecordingDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        perms: perms_for_template,
        recording: recording_vm,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html).into_response())
}

/// Download the raw recording artefact.
///
/// SSH sessions ship the `.cast` file directly. RDP sessions stream a
/// `.zip` (uncompressed `Stored` method, no CPU cost) of every segment
/// `NNN.mp4` plus `manifest.mpd` and `meta.json`, with no
/// re-encoding. Authorization mirrors [`recording_detail`].
//
// allow-uuid-lookup: post-mortem recording artefact download.
pub async fn download_recording(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(session_uuid): axum::extract::Path<::uuid::Uuid>,
) -> Result<axum::response::Response, AppError> {
    use axum::body::Body;
    use axum::http::header;
    use tokio_util::io::ReaderStream;

    if !perms.admin_view {
        return Err(AppError::NotFound("Not found".to_string()));
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    use crate::schema::proxy_sessions::dsl;
    let (session_uuid_db, session_type, recording_path_opt, is_recorded): (
        ::uuid::Uuid,
        SessionType,
        Option<String>,
        bool,
    ) = match dsl::proxy_sessions
        .filter(dsl::uuid.eq(session_uuid))
        .select((
            dsl::uuid,
            dsl::session_type,
            dsl::recording_path,
            dsl::is_recorded,
        ))
        .first(&mut conn)
        .await
    {
        Ok(r) => r,
        Err(_) => return Err(AppError::NotFound("Not found".to_string())),
    };

    if !is_recorded {
        return Err(AppError::NotFound("Not found".to_string()));
    }

    let recording_path =
        recording_path_opt.ok_or_else(|| AppError::NotFound("Not found".to_string()))?;

    let supervisor = state
        .supervisor
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Requires supervisor (SCM_RIGHTS)")))?;

    let storage_base = &state.config.recording.storage_path;
    let base_dir = recording_path
        .strip_prefix(storage_base)
        .unwrap_or(&recording_path)
        .trim_start_matches('/');

    match session_type {
        SessionType::Ssh => {
            let cast_relative = format!("{}session.cast", base_dir);
            let result = supervisor
                .request_recording_file(&session_uuid_db.to_string(), &cast_relative)
                .await
                .map_err(|e| {
                    AppError::Internal(anyhow::anyhow!("Supervisor request failed: {}", e))
                })?;

            if !result.success {
                return Err(AppError::NotFound("Recording file missing".to_string()));
            }

            let std_file = result.file.ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!("Supervisor returned success but no FD"))
            })?;
            let tokio_file = tokio::fs::File::from_std(std_file);
            let stream = ReaderStream::with_capacity(tokio_file, 64 * 1024);
            let filename = format!("{}.cast", session_uuid_db);
            axum::http::Response::builder()
                .header(header::CONTENT_TYPE, "application/x-asciicast")
                .header(
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", filename),
                )
                .body(Body::from_stream(stream))
                .map_err(|e| AppError::Internal(anyhow::anyhow!("Response build error: {}", e)))
        }
        SessionType::Rdp => stream_rdp_zip(&state, &session_uuid_db, base_dir).await,
        SessionType::IacsTunnel => stream_iacs_pcap_zip(&state, &session_uuid_db, base_dir).await,
    }
}

/// Build a streaming ZIP containing every segment `NNN.mp4` plus
/// `manifest.mpd` (rendered on the fly via the existing
/// `build_mpd_xml`) and the raw `meta.json`. Uses the `Stored`
/// compression method (no compression, no CPU work) since the
/// segments are already compressed elementary streams.
async fn stream_rdp_zip(
    state: &AppState,
    session_uuid: &::uuid::Uuid,
    base_dir: &str,
) -> Result<axum::response::Response, AppError> {
    use async_zip::base::write::ZipFileWriter;
    use async_zip::{Compression, ZipEntryBuilder};
    use axum::body::Body;
    use axum::http::header;
    use futures_util::io::AsyncWriteExt as FuturesAsyncWriteExt;
    use tokio::io::{AsyncReadExt, duplex};
    use tokio_util::io::ReaderStream;

    let supervisor = state
        .supervisor
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Requires supervisor")))?;

    // Read meta.json to discover the segment list.
    let meta_relative = format!("{}meta.json", base_dir);
    let meta_result = supervisor
        .request_recording_file(&session_uuid.to_string(), &meta_relative)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Supervisor failed: {}", e)))?;

    if !meta_result.success {
        return Err(AppError::NotFound("meta.json missing".to_string()));
    }

    let meta_file = meta_result
        .file
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("No FD for meta.json")))?;
    let mut tokio_meta = tokio::fs::File::from_std(meta_file);
    let mut meta_buf = Vec::new();
    tokio_meta
        .read_to_end(&mut meta_buf)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("read meta.json: {}", e)))?;

    let meta: RecordingMeta = serde_json::from_slice(&meta_buf)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("invalid meta.json: {}", e)))?;

    // Pre-fetch every segment FD (and the manifest content) BEFORE
    // starting the streaming response, so a missing segment surfaces
    // as a 404 rather than a truncated download.
    let manifest_xml = build_mpd_xml(&session_uuid.to_string(), &meta.segments);

    let mut segments: Vec<(String, std::fs::File)> = Vec::with_capacity(meta.segments.len());
    for seg in &meta.segments {
        // Segment files on disk are written by `vauban-audit` with a
        // three-digit zero-padded index (`001.mp4`, `002.mp4`, ...).
        // See `vauban-audit/src/recording_manager.rs::compute_relative_path`
        // and `build_mpd_xml` below, which both encode the index as
        // `{:03}`. The ZIP entry name mirrors the on-disk layout so
        // the archive can be re-played end-to-end with the bundled
        // `manifest.mpd` without renaming.
        let seg_relative = format!("{}{:03}.mp4", base_dir, seg.index);
        let seg_result = supervisor
            .request_recording_file(&session_uuid.to_string(), &seg_relative)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Supervisor failed: {}", e)))?;
        if !seg_result.success {
            return Err(AppError::NotFound(format!(
                "segment {:03} missing",
                seg.index
            )));
        }
        let seg_file = seg_result.file.ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!("No FD for segment {:03}", seg.index))
        })?;
        segments.push((format!("{:03}.mp4", seg.index), seg_file));
    }

    // Stream the ZIP through a tokio::io::DuplexStream into the
    // response body. Capacity is generous (64 KiB) so the writer side
    // does not block on small frames.
    let (writer, reader) = duplex(64 * 1024);
    let session_uuid_owned = *session_uuid;
    tokio::spawn(async move {
        let mut zip = ZipFileWriter::with_tokio(writer);

        // 1) meta.json
        let entry = ZipEntryBuilder::new("meta.json".into(), Compression::Stored).build();
        if let Ok(mut e) = zip.write_entry_stream(entry).await {
            let _ = e.write_all(&meta_buf).await;
            let _ = e.close().await;
        }

        // 2) manifest.mpd
        let entry = ZipEntryBuilder::new("manifest.mpd".into(), Compression::Stored).build();
        if let Ok(mut e) = zip.write_entry_stream(entry).await {
            let _ = e.write_all(manifest_xml.as_bytes()).await;
            let _ = e.close().await;
        }

        // 3) Each segment NNN.mp4
        for (name, file) in segments {
            let entry = ZipEntryBuilder::new(name.into(), Compression::Stored).build();
            let mut tokio_file = tokio::fs::File::from_std(file);
            let mut buf = vec![0u8; 64 * 1024];
            if let Ok(mut e) = zip.write_entry_stream(entry).await {
                loop {
                    match tokio_file.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if e.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = e.close().await;
            }
        }

        let _ = zip.close().await;
        tracing::debug!(session_uuid = %session_uuid_owned, "rdp zip stream complete");
    });

    let stream = ReaderStream::with_capacity(reader, 64 * 1024);
    let filename = format!("{}.zip", session_uuid);
    axum::http::Response::builder()
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from_stream(stream))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Response build error: {}", e)))
}

/// Stream a ZIP of `meta.json` + every `channels/NNN.pcap.gz` for an IACS session.
async fn stream_iacs_pcap_zip(
    state: &AppState,
    session_uuid: &::uuid::Uuid,
    base_dir: &str,
) -> Result<axum::response::Response, AppError> {
    use async_zip::base::write::ZipFileWriter;
    use async_zip::{Compression, ZipEntryBuilder};
    use axum::body::Body;
    use axum::http::header;
    use futures_util::io::AsyncWriteExt as FuturesAsyncWriteExt;
    use tokio::io::{AsyncReadExt, duplex};
    use tokio_util::io::ReaderStream;

    let supervisor = state
        .supervisor
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Requires supervisor")))?;

    let meta_relative = format!("{}meta.json", base_dir);
    let meta_result = supervisor
        .request_recording_file(&session_uuid.to_string(), &meta_relative)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Supervisor failed: {}", e)))?;
    if !meta_result.success {
        return Err(AppError::NotFound("meta.json missing".to_string()));
    }
    let meta_file = meta_result
        .file
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("No FD for meta.json")))?;
    let mut tokio_meta = tokio::fs::File::from_std(meta_file);
    let mut meta_buf = Vec::new();
    tokio_meta
        .read_to_end(&mut meta_buf)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("read meta.json: {}", e)))?;

    #[derive(serde::Deserialize)]
    struct IacsChannelFile {
        file: String,
    }
    #[derive(serde::Deserialize)]
    struct IacsPcapBundleMeta {
        channels: Vec<IacsChannelFile>,
    }
    let meta: IacsPcapBundleMeta = serde_json::from_slice(&meta_buf)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("invalid meta.json: {}", e)))?;

    let mut channel_files: Vec<(String, std::fs::File)> = Vec::with_capacity(meta.channels.len());
    for ch in &meta.channels {
        let ch_relative = format!("{}{}", base_dir, ch.file);
        let ch_result = supervisor
            .request_recording_file(&session_uuid.to_string(), &ch_relative)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Supervisor failed: {}", e)))?;
        if !ch_result.success {
            return Err(AppError::NotFound(format!(
                "channel file {} missing",
                ch.file
            )));
        }
        let ch_file = ch_result
            .file
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("No FD for channel {}", ch.file)))?;
        channel_files.push((ch.file.clone(), ch_file));
    }

    let (writer, reader) = duplex(64 * 1024);
    let session_uuid_owned = *session_uuid;
    tokio::spawn(async move {
        let mut zip = ZipFileWriter::with_tokio(writer);
        let entry = ZipEntryBuilder::new("meta.json".into(), Compression::Stored).build();
        if let Ok(mut e) = zip.write_entry_stream(entry).await {
            let _ = e.write_all(&meta_buf).await;
            let _ = e.close().await;
        }
        for (name, file) in channel_files {
            let entry = ZipEntryBuilder::new(name.into(), Compression::Stored).build();
            let mut tokio_file = tokio::fs::File::from_std(file);
            let mut buf = vec![0u8; 64 * 1024];
            if let Ok(mut e) = zip.write_entry_stream(entry).await {
                loop {
                    match tokio_file.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if e.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = e.close().await;
            }
        }
        let _ = zip.close().await;
        tracing::debug!(session_uuid = %session_uuid_owned, "iacs pcap zip stream complete");
    });

    let stream = ReaderStream::with_capacity(reader, 64 * 1024);
    let filename = format!("{}.zip", session_uuid);
    axum::http::Response::builder()
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from_stream(stream))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Response build error: {}", e)))
}

// =====================================================================
// IACS Inspect Capture - in-browser packet analyzer.
// =====================================================================
//
// Three handlers, all gated on `perms.admin_view` with anti-enumeration
// 404 (mirroring `recording_detail`):
//
// - `inspect_capture`              -> full HTML shell (initial paint).
// - `inspect_capture_packet_list`  -> HTMX fragment (filter/page/channel).
// - `inspect_capture_packet_detail`-> HTMX fragment (row click).
//
// FD brokering reuses the same supervisor pattern as `stream_iacs_pcap_zip`.

#[derive(serde::Deserialize, Debug, Clone)]
struct IacsInspectChannelMeta {
    #[serde(default)]
    index: u32,
    #[serde(default)]
    target_host: String,
    #[serde(default)]
    target_port: u16,
    #[serde(default)]
    file: String,
    #[serde(default)]
    packet_count: u64,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct IacsInspectMeta {
    #[serde(default)]
    channels: Vec<IacsInspectChannelMeta>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub struct InspectQuery {
    #[serde(default)]
    pub channel: Option<u32>,
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub page: Option<usize>,
    #[serde(default)]
    pub page_size: Option<usize>,
}

/// Resolve the IACS recording identified by `session_uuid` against the
/// caller permissions and return `(session_uuid_db, base_dir,
/// industrial_protocol, asset_name, asset_hostname)`.
///
/// Returns the same generic 404 for every "not found / not IACS / not
/// finalized" path so the URL space is unenumerable.
async fn resolve_inspect_target(
    state: &AppState,
    session_uuid: ::uuid::Uuid,
) -> Result<(::uuid::Uuid, String, String, String, String), AppError> {
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    use crate::schema::proxy_sessions::dsl as ps;
    type InspectTargetRow = (
        ::uuid::Uuid,
        SessionType,
        Option<String>,
        bool,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        String,
        String,
    );
    let row: InspectTargetRow = match ps::proxy_sessions
        .inner_join(schema_assets::table)
        .filter(ps::uuid.eq(session_uuid))
        .filter(ps::is_recorded.eq(true))
        .select((
            ps::uuid,
            ps::session_type,
            ps::recording_path,
            ps::is_recorded,
            ps::recording_finalized_at,
            ps::industrial_protocol,
            schema_assets::name,
            schema_assets::hostname,
        ))
        .first(&mut conn)
        .await
    {
        Ok(r) => r,
        Err(_) => return Err(AppError::NotFound("Not found".to_string())),
    };

    let (
        s_uuid,
        s_type,
        s_path,
        _is_recorded,
        s_finalized_at,
        s_industrial_protocol,
        asset_name,
        asset_hostname,
    ) = row;

    if s_type != SessionType::IacsTunnel || s_finalized_at.is_none() {
        return Err(AppError::NotFound("Not found".to_string()));
    }
    let recording_path = s_path.ok_or_else(|| AppError::NotFound("Not found".to_string()))?;
    let storage_base = &state.config.recording.storage_path;
    let base_dir = recording_path
        .strip_prefix(storage_base)
        .unwrap_or(&recording_path)
        .trim_start_matches('/')
        .to_string();

    Ok((
        s_uuid,
        base_dir,
        s_industrial_protocol.unwrap_or_else(|| "tcp".to_string()),
        asset_name,
        asset_hostname,
    ))
}

/// Fetch and deserialize meta.json for the IACS recording.
async fn fetch_inspect_meta(
    state: &AppState,
    session_uuid: ::uuid::Uuid,
    base_dir: &str,
) -> Result<IacsInspectMeta, AppError> {
    use tokio::io::AsyncReadExt;
    let supervisor = state
        .supervisor
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Requires supervisor")))?;
    let meta_relative = format!("{}meta.json", base_dir);
    let result = supervisor
        .request_recording_file(&session_uuid.to_string(), &meta_relative)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Supervisor failed: {}", e)))?;
    if !result.success {
        return Err(AppError::NotFound("Not found".to_string()));
    }
    let std_file = result
        .file
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("No FD for meta.json")))?;
    let mut tokio_file = tokio::fs::File::from_std(std_file);
    let mut buf = Vec::new();
    tokio_file
        .read_to_end(&mut buf)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Read meta: {}", e)))?;
    let meta: IacsInspectMeta =
        serde_json::from_slice(&buf).map_err(|_| AppError::NotFound("Not found".to_string()))?;
    Ok(meta)
}

/// Fetch the gzipped PCAP for one channel and return the decompressed
/// raw bytes ready for `analyze_channel_bytes` / `analyze_packet_bytes`.
async fn fetch_inspect_channel_pcap(
    state: &AppState,
    session_uuid: ::uuid::Uuid,
    base_dir: &str,
    channel_file: &str,
) -> Result<Vec<u8>, AppError> {
    use std::io::Read as _;
    use tokio::io::AsyncReadExt;
    let supervisor = state
        .supervisor
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Requires supervisor")))?;
    let relative = format!("{}{}", base_dir, channel_file);
    let result = supervisor
        .request_recording_file(&session_uuid.to_string(), &relative)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Supervisor failed: {}", e)))?;
    if !result.success {
        return Err(AppError::NotFound("Not found".to_string()));
    }
    let std_file = result
        .file
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("No FD for channel pcap")))?;
    let mut tokio_file = tokio::fs::File::from_std(std_file);
    let mut gz = Vec::new();
    tokio_file
        .read_to_end(&mut gz)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Read pcap.gz: {}", e)))?;
    let mut decoder = flate2::read::GzDecoder::new(&gz[..]);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|_| AppError::NotFound("Not found".to_string()))?;
    Ok(decompressed)
}

fn build_filter_view(
    query: &InspectQuery,
) -> crate::templates::sessions::inspect_capture::InspectFilterViewModel {
    crate::templates::sessions::inspect_capture::InspectFilterViewModel {
        direction: query.direction.clone().filter(|s| !s.is_empty()),
        kind: query.kind.clone().filter(|s| !s.is_empty()),
        search: query.search.clone().filter(|s| !s.trim().is_empty()),
        page: query.page.unwrap_or(1),
        page_size: query
            .page_size
            .unwrap_or(crate::services::iacs_packet_analyzer::types::DEFAULT_PAGE_SIZE),
    }
}

fn build_packet_list_view(
    page: crate::services::iacs_packet_analyzer::types::PacketListPage,
    session_uuid: &str,
    channel: u32,
    filter: crate::templates::sessions::inspect_capture::InspectFilterViewModel,
) -> crate::templates::sessions::inspect_capture::PacketListViewModel {
    use crate::templates::sessions::inspect_capture::{PacketListViewModel, PacketRowViewModel};
    let page_size = page.page_size.max(1);
    let total_pages = page.total.div_ceil(page_size);
    let has_prev = page.page > 1;
    let has_next = page.page < total_pages;
    let first_frame_idx = <[_]>::first(&page.items).map(|s| s.frame_idx);
    let items: Vec<PacketRowViewModel> = page
        .items
        .iter()
        .map(|s| PacketRowViewModel::from_summary(s, session_uuid, channel))
        .collect();
    PacketListViewModel {
        session_uuid: session_uuid.to_string(),
        channel,
        items,
        total: page.total,
        page: page.page,
        page_size: page.page_size,
        total_pages,
        has_prev,
        has_next,
        filter,
        first_frame_idx,
    }
}

fn industrial_to_profile(p: &str) -> shared::iacs_protocol::ExpectedProfile {
    shared::iacs_protocol::ExpectedProfile::from_industrial_label(p)
}

/// Inspect Capture page (full HTML shell).
//
// allow-uuid-lookup: post-mortem recording inspector.
pub async fn inspect_capture(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    axum::extract::Path(session_uuid): axum::extract::Path<::uuid::Uuid>,
    axum::extract::Query(query): axum::extract::Query<InspectQuery>,
) -> Result<axum::response::Response, AppError> {
    use crate::services::iacs_packet_analyzer::{
        analyze_channel_bytes, page_summaries, types::PacketListFilter,
    };
    use crate::templates::sessions::inspect_capture::{
        ChannelOption, InspectCaptureTemplate, InspectCaptureViewModel, industrial_protocol_label,
    };

    if !perms.admin_view {
        return Err(AppError::NotFound("Not found".to_string()));
    }

    let (s_uuid, base_dir, industrial_protocol, asset_name, asset_hostname) =
        resolve_inspect_target(&state, session_uuid).await?;

    let meta = fetch_inspect_meta(&state, s_uuid, &base_dir).await?;
    if meta.channels.is_empty() {
        return Err(AppError::NotFound("Not found".to_string()));
    }

    let selected_channel = query
        .channel
        .filter(|c| meta.channels.iter().any(|m| m.index == *c))
        .unwrap_or(meta.channels[0].index);

    let target_channel = meta
        .channels
        .iter()
        .find(|c| c.index == selected_channel)
        .ok_or_else(|| AppError::NotFound("Not found".to_string()))?;

    let pcap = fetch_inspect_channel_pcap(&state, s_uuid, &base_dir, &target_channel.file).await?;
    let profile = industrial_to_profile(&industrial_protocol);
    let summaries = analyze_channel_bytes(&pcap, profile)
        .map_err(|_| AppError::NotFound("Not found".to_string()))?;

    let filter_view = build_filter_view(&query);
    let filter = PacketListFilter {
        direction: filter_view
            .direction
            .as_deref()
            .and_then(crate::services::iacs_packet_analyzer::types::Direction::parse),
        kind: filter_view
            .kind
            .as_deref()
            .and_then(crate::services::iacs_packet_analyzer::types::PacketKind::parse),
        search: filter_view.search.clone(),
        page: filter_view.page,
        page_size: filter_view.page_size,
    };

    let page = page_summaries(summaries, filter);
    let session_uuid_str = s_uuid.to_string();
    let initial_list =
        build_packet_list_view(page, &session_uuid_str, selected_channel, filter_view);

    let channels: Vec<ChannelOption> = meta
        .channels
        .iter()
        .map(|c| ChannelOption {
            index: c.index,
            label: format!("ch{:03}", c.index),
            target: format!("{}:{}", c.target_host, c.target_port),
            packets: c.packet_count,
        })
        .collect();

    let view = InspectCaptureViewModel {
        session_uuid: session_uuid_str.clone(),
        asset_name: asset_name.clone(),
        asset_hostname,
        industrial_protocol_label: industrial_protocol_label(&industrial_protocol).to_string(),
        industrial_protocol,
        channels,
        selected_channel,
        back_url: format!("/sessions/recordings/{}", session_uuid_str),
        list_url: "/sessions/recordings".to_string(),
        recording_detail_url: format!("/sessions/recordings/{}", session_uuid_str),
        initial_list,
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(
        format!("Inspect Capture - {}", asset_name),
        user.clone(),
        browser_tz.0,
    )
    .with_current_path("/sessions/recordings");
    let perms_for_template = perms.clone();
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = InspectCaptureTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        perms: perms_for_template,
        view,
    };
    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render: {}", e)))?;
    Ok(Html(html).into_response())
}

/// HTMX fragment: paginated packet list for one channel.
//
// allow-uuid-lookup: post-mortem recording inspector fragment.
pub async fn inspect_capture_packet_list(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path((session_uuid, channel)): axum::extract::Path<(::uuid::Uuid, u32)>,
    axum::extract::Query(query): axum::extract::Query<InspectQuery>,
) -> Result<axum::response::Response, AppError> {
    use crate::services::iacs_packet_analyzer::{
        analyze_channel_bytes, page_summaries, types::PacketListFilter,
    };
    use crate::templates::sessions::inspect_capture::PacketListPartial;

    if !perms.admin_view {
        return Err(AppError::NotFound("Not found".to_string()));
    }

    let (s_uuid, base_dir, industrial_protocol, _, _) =
        resolve_inspect_target(&state, session_uuid).await?;
    let meta = fetch_inspect_meta(&state, s_uuid, &base_dir).await?;
    let target = meta
        .channels
        .iter()
        .find(|c| c.index == channel)
        .ok_or_else(|| AppError::NotFound("Not found".to_string()))?;
    let pcap = fetch_inspect_channel_pcap(&state, s_uuid, &base_dir, &target.file).await?;

    let profile = industrial_to_profile(&industrial_protocol);
    let summaries = analyze_channel_bytes(&pcap, profile)
        .map_err(|_| AppError::NotFound("Not found".to_string()))?;

    let filter_view = build_filter_view(&query);
    let filter = PacketListFilter {
        direction: filter_view
            .direction
            .as_deref()
            .and_then(crate::services::iacs_packet_analyzer::types::Direction::parse),
        kind: filter_view
            .kind
            .as_deref()
            .and_then(crate::services::iacs_packet_analyzer::types::PacketKind::parse),
        search: filter_view.search.clone(),
        page: filter_view.page,
        page_size: filter_view.page_size,
    };

    let page = page_summaries(summaries, filter);
    let session_uuid_str = s_uuid.to_string();
    let list = build_packet_list_view(page, &session_uuid_str, channel, filter_view);

    let template = PacketListPartial { list };
    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render: {}", e)))?;
    Ok(Html(html).into_response())
}

/// HTMX fragment: full dissection of one frame.
//
// allow-uuid-lookup: post-mortem recording inspector fragment.
pub async fn inspect_capture_packet_detail(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path((session_uuid, channel, frame_idx)): axum::extract::Path<(
        ::uuid::Uuid,
        u32,
        usize,
    )>,
) -> Result<axum::response::Response, AppError> {
    use crate::services::iacs_packet_analyzer::analyze_packet_bytes;
    use crate::templates::sessions::inspect_capture::{PacketDetailPartial, PacketDetailViewModel};

    if !perms.admin_view {
        return Err(AppError::NotFound("Not found".to_string()));
    }
    if frame_idx == 0 {
        return Err(AppError::NotFound("Not found".to_string()));
    }

    let (s_uuid, base_dir, industrial_protocol, _, _) =
        resolve_inspect_target(&state, session_uuid).await?;
    let meta = fetch_inspect_meta(&state, s_uuid, &base_dir).await?;
    let target = meta
        .channels
        .iter()
        .find(|c| c.index == channel)
        .ok_or_else(|| AppError::NotFound("Not found".to_string()))?;
    let pcap = fetch_inspect_channel_pcap(&state, s_uuid, &base_dir, &target.file).await?;

    let profile = industrial_to_profile(&industrial_protocol);
    let detail = analyze_packet_bytes(&pcap, profile, frame_idx)
        .ok_or_else(|| AppError::NotFound("Not found".to_string()))?;
    let session_uuid_str = s_uuid.to_string();
    let vm = PacketDetailViewModel::from_detail(detail, &session_uuid_str, channel);

    let template = PacketDetailPartial { detail: vm };
    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render: {}", e)))?;
    Ok(Html(html).into_response())
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
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(session_uuid_str): axum::extract::Path<String>,
) -> Result<axum::response::Response, AppError> {
    use axum::body::Body;
    use axum::http::{StatusCode, header};

    if !perms.admin_view {
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
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    headers: axum::http::HeaderMap,
    axum::extract::Path((session_uuid_str, segment_str)): axum::extract::Path<(String, String)>,
) -> Result<axum::response::Response, AppError> {
    use axum::body::Body;
    use axum::http::{StatusCode, header};
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    use tokio_util::io::ReaderStream;

    if !perms.admin_view {
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
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(session_uuid_str): axum::extract::Path<String>,
) -> Result<axum::response::Response, AppError> {
    use axum::body::Body;
    use axum::http::header;
    use tokio_util::io::ReaderStream;

    if !perms.admin_view {
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

    // ---- ApproveForm deserialization tests ----
    //
    // HTML forms use application/x-www-form-urlencoded, which sends all
    // values as strings. An empty <input type="number"> sends "".
    // These tests verify the custom deserializer handles all edge cases.

    #[test]
    fn test_approve_form_deser_empty_duration_value_treated_as_none() {
        let form = "csrf_token=tok&duration_value=&duration_unit=minutes";
        let parsed: ApproveForm = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(parsed.duration_value, None);
        assert_eq!(parsed.duration_unit.as_deref(), Some("minutes"));
    }

    #[test]
    fn test_approve_form_deser_missing_duration_fields() {
        let form = "csrf_token=tok";
        let parsed: ApproveForm = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(parsed.duration_value, None);
        assert_eq!(parsed.duration_unit, None);
    }

    #[test]
    fn test_approve_form_deser_numeric_string_duration() {
        let form = "csrf_token=tok&duration_value=15&duration_unit=minutes";
        let parsed: ApproveForm = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(parsed.duration_value, Some(15));
    }

    #[test]
    fn test_approve_form_deser_large_numeric_duration() {
        let form = "csrf_token=tok&duration_value=24&duration_unit=hours";
        let parsed: ApproveForm = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(parsed.duration_value, Some(24));
        assert_eq!(parsed.resolve_duration_seconds().unwrap(), Some(86400),);
    }

    #[test]
    fn test_approve_form_deser_non_numeric_duration_fails() {
        let form = "csrf_token=tok&duration_value=abc&duration_unit=minutes";
        let result: Result<ApproveForm, _> = serde_urlencoded::from_str(form);
        assert!(result.is_err());
    }

    #[test]
    fn test_approve_form_deser_duration_value_only_no_unit() {
        let form = "csrf_token=tok&duration_value=10";
        let parsed: ApproveForm = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(parsed.duration_value, Some(10));
        assert_eq!(parsed.duration_unit, None);
    }

    #[test]
    fn test_approve_form_deser_csrf_preserved() {
        let form = "csrf_token=my-secure-token&duration_value=5&duration_unit=hours";
        let parsed: ApproveForm = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(parsed.csrf_token, "my-secure-token");
    }

    #[test]
    fn test_approve_form_deser_empty_unit_treated_as_some_empty() {
        let form = "csrf_token=tok&duration_value=5&duration_unit=";
        let parsed: ApproveForm = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(parsed.duration_value, Some(5));
        assert_eq!(parsed.duration_unit.as_deref(), Some(""));
    }

    #[test]
    fn test_approve_form_roundtrip_resolve_empty_returns_none() {
        let form = "csrf_token=tok&duration_value=&duration_unit=minutes";
        let parsed: ApproveForm = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(parsed.resolve_duration_seconds().unwrap(), None);
    }

    #[test]
    fn test_approve_form_roundtrip_resolve_valid_returns_seconds() {
        let form = "csrf_token=tok&duration_value=30&duration_unit=minutes";
        let parsed: ApproveForm = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(parsed.resolve_duration_seconds().unwrap(), Some(1800));
    }

    #[test]
    fn test_approve_form_roundtrip_resolve_zero_rejected() {
        let form = "csrf_token=tok&duration_value=0&duration_unit=minutes";
        let parsed: ApproveForm = serde_urlencoded::from_str(form).unwrap();
        assert!(parsed.resolve_duration_seconds().is_err());
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

    // ---- broadcast_approval_badge structural tests ----

    #[test]
    fn test_broadcast_approval_badge_handler_exists() {
        let source = include_str!("sessions.rs");
        assert!(
            source.contains("async fn broadcast_approval_badge"),
            "broadcast_approval_badge helper must exist"
        );
    }

    #[test]
    fn test_broadcast_approval_badge_called_after_submit() {
        let source = include_str!("sessions.rs");
        let submit_fn = source
            .find("fn submit_access_request")
            .expect("submit_access_request must exist");
        let next_fn = source[submit_fn..]
            .find("\npub async fn ")
            .map(|p| submit_fn + p)
            .unwrap_or(source.len());
        let body = &source[submit_fn..next_fn];
        assert!(
            body.contains("broadcast_approval_badge"),
            "submit_access_request must call broadcast_approval_badge"
        );
    }

    #[test]
    fn test_broadcast_approval_badge_called_after_approve() {
        let source = include_str!("sessions.rs");
        // After the SoD refactoring, approve_access_request delegates to
        // dispatch_approval_decision which calls broadcast_approval_badge.
        // Verify the call chain: approve → dispatch → broadcast.
        let approve_fn = source
            .find("fn approve_access_request")
            .expect("approve_access_request must exist");
        let next_fn = source[approve_fn..]
            .find("\npub async fn ")
            .map(|p| approve_fn + p)
            .unwrap_or(source.len());
        let body = &source[approve_fn..next_fn];
        assert!(
            body.contains("dispatch_approval_decision"),
            "approve_access_request must delegate to dispatch_approval_decision"
        );
        let dispatch_fn = source
            .find("fn dispatch_approval_decision")
            .expect("dispatch_approval_decision must exist");
        let dispatch_end = source[dispatch_fn..]
            .find("\nfn ")
            .or_else(|| source[dispatch_fn..].find("\nasync fn "))
            .map(|p| dispatch_fn + p)
            .unwrap_or(source.len());
        let dispatch_body = &source[dispatch_fn..dispatch_end];
        assert!(
            dispatch_body.contains("broadcast_approval_badge"),
            "dispatch_approval_decision must call broadcast_approval_badge"
        );
    }

    #[test]
    fn test_broadcast_approval_badge_called_after_reject() {
        let source = include_str!("sessions.rs");
        // Same delegation chain as approve.
        let reject_fn = source
            .find("fn reject_access_request")
            .expect("reject_access_request must exist");
        let next_fn = source[reject_fn..]
            .find("\npub async fn ")
            .map(|p| reject_fn + p)
            .unwrap_or(source.len());
        let body = &source[reject_fn..next_fn];
        assert!(
            body.contains("dispatch_approval_decision"),
            "reject_access_request must delegate to dispatch_approval_decision"
        );
    }

    #[test]
    fn test_broadcast_approval_badge_called_after_cancel() {
        let source = include_str!("sessions.rs");
        let cancel_fn = source
            .find("fn cancel_access_request")
            .expect("cancel_access_request must exist");
        let next_fn = source[cancel_fn..]
            .find("\npub async fn ")
            .map(|p| cancel_fn + p)
            .unwrap_or(source.len());
        let body = &source[cancel_fn..next_fn];
        assert!(
            body.contains("broadcast_approval_badge"),
            "cancel_access_request must call broadcast_approval_badge"
        );
    }

    #[test]
    fn test_cancel_broadcasts_request_cancelled_event() {
        let source = include_str!("sessions.rs");
        let cancel_fn = source
            .find("fn cancel_access_request")
            .expect("cancel_access_request must exist");
        let next_fn = source[cancel_fn..]
            .find("\npub async fn ")
            .map(|p| cancel_fn + p)
            .unwrap_or(source.len());
        let body = &source[cancel_fn..next_fn];
        assert!(
            body.contains("request_cancelled"),
            "cancel_access_request must broadcast request_cancelled event"
        );
    }

    #[test]
    fn test_my_requests_includes_all_lifecycle_statuses() {
        let source = include_str!("sessions.rs");
        let my_req_fn = source
            .find("fn my_requests")
            .expect("my_requests handler must exist");
        let next_fn = source[my_req_fn..]
            .find("\npub async fn ")
            .map(|p| my_req_fn + p)
            .unwrap_or(source.len());
        let body = &source[my_req_fn..next_fn];

        for status in &[
            "pending",
            "approved",
            "rejected",
            "expired",
            "consumed",
            "active",
            "disconnected",
            "terminated",
        ] {
            assert!(
                body.contains(&format!("\"{}\"", status)),
                "my_requests handler must include status '{}'",
                status
            );
        }
    }

    #[test]
    fn test_my_requests_filters_by_justification_not_null() {
        let source = include_str!("sessions.rs");
        let my_req_fn = source
            .find("fn my_requests")
            .expect("my_requests handler must exist");
        let next_fn = source[my_req_fn..]
            .find("\npub async fn ")
            .map(|p| my_req_fn + p)
            .unwrap_or(source.len());
        let body = &source[my_req_fn..next_fn];

        assert!(
            body.contains("justification.is_not_null()"),
            "my_requests must filter on justification.is_not_null() to exclude direct connections"
        );
    }

    #[test]
    fn test_my_requests_per_page_is_30() {
        assert_eq!(
            MY_REQUESTS_PER_PAGE, 30,
            "my_requests should paginate at 30 items"
        );
    }

    #[test]
    fn test_my_requests_handler_uses_pagination() {
        let source = include_str!("sessions.rs");
        let my_req_fn = source
            .find("fn my_requests")
            .expect("my_requests handler must exist");
        let next_fn = source[my_req_fn..]
            .find("\npub async fn ")
            .or_else(|| source[my_req_fn..].find("\nconst "))
            .map(|p| my_req_fn + p)
            .unwrap_or(source.len());
        let body = &source[my_req_fn..next_fn];

        assert!(body.contains(".count()"), "must use COUNT query");
        assert!(body.contains(".offset("), "must use OFFSET");
        assert!(
            body.contains("MY_REQUESTS_PER_PAGE"),
            "must reference per-page constant"
        );
        assert!(
            body.contains("Pagination {"),
            "must construct Pagination struct"
        );
    }

    #[test]
    fn test_my_requests_handler_parses_page_param() {
        let source = include_str!("sessions.rs");
        let my_req_fn = source
            .find("fn my_requests")
            .expect("my_requests handler must exist");
        let next_fn = source[my_req_fn..]
            .find("\npub async fn ")
            .or_else(|| source[my_req_fn..].find("\nconst "))
            .map(|p| my_req_fn + p)
            .unwrap_or(source.len());
        let body = &source[my_req_fn..next_fn];

        assert!(body.contains("\"page\""), "must extract page parameter");
        assert!(body.contains(".max(1)"), "must clamp page to min 1");
        assert!(
            body.contains(".min(total_pages)"),
            "must clamp page to max total_pages"
        );
    }

    #[test]
    fn test_broadcast_badge_targets_sidebar_approval_badge() {
        let source = include_str!("sessions.rs");
        let badge_fn = source
            .find("fn broadcast_approval_badge")
            .expect("broadcast_approval_badge must exist");
        let next_fn = source[badge_fn..]
            .find("\nfn ")
            .or_else(|| source[badge_fn..].find("\npub "))
            .or_else(|| source[badge_fn..].find("\nasync fn "))
            .map(|p| badge_fn + p)
            .unwrap_or(source.len());
        let body = &source[badge_fn..next_fn];
        assert!(
            body.contains("sidebar-approval-badge"),
            "broadcast_approval_badge must target sidebar-approval-badge"
        );
        assert!(
            body.contains("hx-swap-oob"),
            "broadcast_approval_badge must use hx-swap-oob"
        );
    }

    // ---- approval_detail flash-message anti-regression (BUG-14) ----
    //
    // The POST handlers (approve/reject) use flash_redirect to send
    // a success or error message via the PRG pattern. The GET handler
    // (approval_detail) MUST consume `incoming_flash.messages()` and
    // inject them via `.with_messages(...)`, otherwise the operator
    // never sees the outcome of their action.

    #[test]
    fn approval_detail_consumes_flash_messages() {
        let source = include_str!("sessions.rs");
        let detail_fn = source
            .find("pub async fn approval_detail(")
            .expect("approval_detail handler must exist");
        let next_fn = source[detail_fn..]
            .find("\npub async fn ")
            .map(|p| detail_fn + p)
            .unwrap_or(source.len());
        let body = &source[detail_fn..next_fn];

        assert!(
            body.contains("incoming_flash"),
            "approval_detail must accept IncomingFlash extractor"
        );
        assert!(
            body.contains(".messages()"),
            "approval_detail must read flash messages via .messages()"
        );
        assert!(
            body.contains(".with_messages("),
            "approval_detail must inject flash messages into BaseTemplate via .with_messages()"
        );
    }

    // ---- approval_list status filter anti-regression ----
    //
    // The approval list must only show statuses that belong to the
    // approval lifecycle: pending, approved, rejected, expired,
    // orphaned. Session-state statuses (connecting, active,
    // terminated, disconnected, consumed) must NEVER appear.

    #[test]
    fn approval_list_filters_by_approval_statuses_only() {
        let source = include_str!("sessions.rs");
        let list_fn = source
            .find("pub async fn approval_list(")
            .expect("approval_list handler must exist");
        let next_fn = source[list_fn..]
            .find("\npub async fn ")
            .map(|p| list_fn + p)
            .unwrap_or(source.len());
        let body = &source[list_fn..next_fn];

        assert!(
            body.contains("APPROVAL_STATUSES"),
            "approval_list must reference APPROVAL_STATUSES constant"
        );
        assert!(
            body.contains(".eq_any(APPROVAL_STATUSES)"),
            "approval_list must filter proxy_sessions by APPROVAL_STATUSES"
        );
    }

    #[test]
    fn approval_statuses_contains_only_approval_lifecycle() {
        assert!(
            APPROVAL_STATUSES.contains(&"pending"),
            "APPROVAL_STATUSES must include pending"
        );
        assert!(
            APPROVAL_STATUSES.contains(&"approved"),
            "APPROVAL_STATUSES must include approved"
        );
        assert!(
            APPROVAL_STATUSES.contains(&"rejected"),
            "APPROVAL_STATUSES must include rejected"
        );
        assert!(
            APPROVAL_STATUSES.contains(&"revoked"),
            "APPROVAL_STATUSES must include revoked (post-approval admin cut)"
        );
        assert!(
            APPROVAL_STATUSES.contains(&"expired"),
            "APPROVAL_STATUSES must include expired"
        );
        assert!(
            APPROVAL_STATUSES.contains(&"orphaned"),
            "APPROVAL_STATUSES must include orphaned"
        );
        assert!(
            !APPROVAL_STATUSES.contains(&"connecting"),
            "APPROVAL_STATUSES must NOT include connecting"
        );
        assert!(
            !APPROVAL_STATUSES.contains(&"active"),
            "APPROVAL_STATUSES must NOT include active"
        );
        assert!(
            !APPROVAL_STATUSES.contains(&"terminated"),
            "APPROVAL_STATUSES must NOT include terminated"
        );
        assert!(
            !APPROVAL_STATUSES.contains(&"disconnected"),
            "APPROVAL_STATUSES must NOT include disconnected"
        );
    }

    // ---- decision section in approval detail (BUG-15) ----
    //
    // When decided_by is populated, the detail page must render
    // the "Decision" card so the operator can see who acted.

    #[test]
    fn approval_detail_template_exposes_decided_by_field() {
        let source = include_str!("sessions.rs");
        let detail_fn = source
            .find("pub async fn approval_detail(")
            .expect("approval_detail must exist");
        let next_fn = source[detail_fn..]
            .find("\npub async fn ")
            .map(|p| detail_fn + p)
            .unwrap_or(source.len());
        let body = &source[detail_fn..next_fn];

        assert!(
            body.contains("decided_by"),
            "approval_detail must populate decided_by in ApprovalDetail"
        );
        assert!(
            body.contains("decided_at"),
            "approval_detail must populate decided_at in ApprovalDetail"
        );
        assert!(
            body.contains("decision_reason"),
            "approval_detail must populate decision_reason in ApprovalDetail"
        );
    }

    #[test]
    fn reject_form_has_reason_field() {
        let source = include_str!("sessions.rs");
        let struct_pos = source
            .find("pub struct RejectForm")
            .expect("RejectForm must exist");
        let brace_end = source[struct_pos..]
            .find('}')
            .map(|p| struct_pos + p)
            .unwrap();
        let struct_body = &source[struct_pos..brace_end];
        assert!(
            struct_body.contains("reason"),
            "RejectForm must have a 'reason' field for mandatory rejection motivation"
        );
    }

    #[test]
    fn reject_handler_passes_reason_to_dispatch() {
        let source = include_str!("sessions.rs");
        let reject_fn = source
            .find("fn reject_access_request")
            .expect("reject_access_request must exist");
        let next_fn = source[reject_fn..]
            .find("\npub async fn ")
            .or_else(|| source[reject_fn..].find("\nasync fn "))
            .map(|p| reject_fn + p)
            .unwrap_or(source.len());
        let body = &source[reject_fn..next_fn];
        assert!(
            body.contains("form.reason") || body.contains("reason"),
            "reject_access_request must read and forward the rejection reason"
        );
    }
}
