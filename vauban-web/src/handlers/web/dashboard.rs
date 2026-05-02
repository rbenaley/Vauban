/// Dashboard page handlers.
use super::*;
use crate::models::session::SessionType;

/// Dashboard home page -- the "Bastion Watch" passive operations
/// console. Aggregates system_health + dashboard snapshot +
/// anomalies (admin only) and renders the read-only template.
pub async fn dashboard_home(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::permissions::PermissionContext,
) -> Result<Response, AppError> {
    use crate::services::dashboard::DashboardSnapshot;
    use crate::templates::dashboard::BastionWatchTemplate;

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Bastion Watch".to_string(), user.clone()).with_current_path("/");

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    // Cached system health (5 s TTL): cheap on the hot path.
    let system_health = if perms.admin_view {
        Some(state.system_health_cache.snapshot().await)
    } else {
        None
    };

    let snapshot = DashboardSnapshot::load(
        &state.db_pool,
        &auth_user,
        &perms,
        system_health,
        &state.live_session_history,
    )
    .await;

    let anomalies = if perms.admin_view {
        crate::services::anomalies::detect_all(&state.db_pool).await
    } else {
        Vec::new()
    };

    let template = BastionWatchTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        snapshot,
        anomalies,
        perms,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html).into_response())
}

/// Dashboard admin page.
pub async fn dashboard_admin(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("Admin Dashboard".to_string(), user.clone()).with_current_path("/admin");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

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

/// Dashboard stats widget.
pub async fn dashboard_widget_stats(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
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
    _auth_user: WebAuthUser,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::dashboard::widgets::ActiveSessionItem;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Load active sessions with asset info
    let active_sessions: Vec<(
        i32,
        String,
        String,
        SessionType,
        chrono::DateTime<chrono::Utc>,
    )> = proxy_sessions::table
        .inner_join(schema_assets::table)
        .filter(proxy_sessions::status.eq("active"))
        .select((
            proxy_sessions::id,
            schema_assets::name,
            schema_assets::hostname,
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
                    session_type: session_type.to_string(),
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
    _auth_user: WebAuthUser,
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
