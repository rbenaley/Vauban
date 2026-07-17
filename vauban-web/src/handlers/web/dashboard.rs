/// Dashboard page handlers.
use super::*;

/// Dashboard home page -- the "Bastion Watch" passive operations
/// console.
///
/// SECURITY (per-user isolation, L3 Casbin gate): the request
/// scope is derived from `perms.sessions_supervise`. A supervisor
/// (`sessions:supervise` granted by Casbin) sees the bastion-wide
/// aggregate via `DashboardScope::Global`; every other caller is
/// pinned to `DashboardScope::User(self.user_id)` so loaders inject
/// `WHERE proxy_sessions.user_id = $1`. The compiler enforces the
/// scope-as-mandatory-parameter contract on the loader signatures
/// (L1) and the SQL filter is applied loader-side (L2).
pub async fn dashboard_home(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::permissions::PermissionContext,
    browser_tz: BrowserTz,
) -> Result<Response, AppError> {
    use crate::services::dashboard::{DashboardScope, DashboardSnapshot, snapshot};
    use crate::templates::dashboard::BastionWatchTemplate;

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Bastion Watch".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/");

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    // Resolve the caller's user_id once for the scope decision.
    // Fail-safe: if the user UUID cannot be resolved (corrupt JWT,
    // user just deactivated, ...), pin to a sentinel `User(-1)`
    // scope. -1 cannot match any row in `proxy_sessions.user_id`
    // (positive serial), so the dashboard renders an empty view --
    // strictly safer than upgrading to `Global` on resolution
    // failure.
    let scope = if perms.sessions_supervise {
        DashboardScope::Global
    } else {
        match snapshot::resolve_user_id_from_uuid(&state.db_pool, &auth_user.uuid).await {
            Some(uid) => DashboardScope::User(uid),
            None => DashboardScope::User(-1),
        }
    };

    // Cached system health (5 s TTL): cheap on the hot path. Gated
    // on sessions_supervise (consistent with the rest of the
    // gouvernance/infra surface) -- a non-supervisor never sees
    // pool / req-rate / outbox state.
    let system_health = if perms.sessions_supervise {
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
        scope,
    )
    .await;

    let anomalies = if perms.sessions_supervise {
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
        tz: browser_tz.0,
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
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
) -> Result<impl IntoResponse, AppError> {
    if !perms.admin_view {
        return Err(AppError::forbidden("admin:view"));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Admin Dashboard".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/admin");
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

// The former `dashboard_widget_*` HTMX handlers were removed (BAC
// hardening): they were not mounted in `main.rs`, carried no Casbin
// gate, and ran bastion-wide queries without the per-user scoping
// that `dashboard_home` enforces. The production refresh path is the
// WebSocket pusher in `tasks::dashboard`, which keeps the composite
// `["active", "tunnel_active"]` filter (pinned by
// `bastion_watch_iacs_count_test.rs`).
