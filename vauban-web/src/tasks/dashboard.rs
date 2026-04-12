use askama::Template;
use chrono::Utc;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
/// VAUBAN Web - Dashboard update tasks.
///
/// Background tasks that push dashboard updates via WebSocket.
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, trace};

use crate::utils::format_duration;

use crate::db::DbPool;
use crate::services::broadcast::{BroadcastService, WsChannel, WsMessage};
use crate::templates::dashboard::widgets::{
    ActiveSessionItem, ActiveSessionsWidget, ActivityItem, RecentActivityWidget, StatsData,
    StatsWidget,
};
use crate::templates::sessions::{
    ActiveListContentWidget, ActiveListStatsWidget, ActiveSessionItem as FullActiveSessionItem,
    SessionListContentWidget, SessionListItem,
};

/// Interval for stats updates (30 seconds).
const STATS_INTERVAL_SECS: u64 = 30;

/// Interval for active sessions updates (10 seconds).
const SESSIONS_INTERVAL_SECS: u64 = 10;

/// Interval for recent activity updates (30 seconds).
const ACTIVITY_INTERVAL_SECS: u64 = 30;

/// Start all dashboard update tasks.
pub async fn start_dashboard_tasks(broadcast: BroadcastService, db_pool: DbPool) {
    let broadcast = Arc::new(broadcast);
    let db_pool = Arc::new(db_pool);

    // Spawn stats updater
    let broadcast_clone = Arc::clone(&broadcast);
    let db_clone = Arc::clone(&db_pool);
    tokio::spawn(async move {
        stats_updater(broadcast_clone, db_clone).await;
    });

    // Spawn active sessions updater
    let broadcast_clone = Arc::clone(&broadcast);
    let db_clone = Arc::clone(&db_pool);
    tokio::spawn(async move {
        sessions_updater(broadcast_clone, db_clone).await;
    });

    // Spawn recent activity updater
    let broadcast_clone = Arc::clone(&broadcast);
    let db_clone = Arc::clone(&db_pool);
    tokio::spawn(async move {
        activity_updater(broadcast_clone, db_clone).await;
    });

    // Spawn session list updater (for /sessions page real-time updates)
    let broadcast_clone = Arc::clone(&broadcast);
    let db_clone = Arc::clone(&db_pool);
    tokio::spawn(async move {
        session_list_updater(broadcast_clone, db_clone).await;
    });

    info!("Dashboard background tasks started");
}

/// Task that pushes stats updates.
async fn stats_updater(broadcast: Arc<BroadcastService>, db_pool: Arc<DbPool>) {
    let mut ticker = interval(Duration::from_secs(STATS_INTERVAL_SECS));

    loop {
        ticker.tick().await;

        match fetch_stats(&db_pool).await {
            Ok(stats) => {
                let template = StatsWidget { stats };
                match template.render() {
                    Ok(html) => {
                        let msg = WsMessage::new("ws-stats", html);
                        if broadcast
                            .send(&WsChannel::DashboardStats, msg)
                            .await
                            .is_err()
                        {
                            trace!("No subscribers for stats channel");
                        }
                    }
                    Err(e) => error!(error = %e, "Failed to render stats widget"),
                }
            }
            Err(e) => error!(error = %e, "Failed to fetch stats"),
        }
    }
}

/// Task that pushes active sessions updates.
async fn sessions_updater(broadcast: Arc<BroadcastService>, db_pool: Arc<DbPool>) {
    let mut ticker = interval(Duration::from_secs(SESSIONS_INTERVAL_SECS));

    loop {
        ticker.tick().await;

        // Update dashboard widget (ActiveSessions channel)
        match fetch_active_sessions(&db_pool).await {
            Ok(sessions) => {
                let template = ActiveSessionsWidget { sessions };
                match template.render() {
                    Ok(html) => {
                        let msg = WsMessage::new("ws-active-sessions", html);
                        if broadcast
                            .send(&WsChannel::ActiveSessions, msg)
                            .await
                            .is_err()
                        {
                            trace!("No subscribers for sessions channel");
                        }
                    }
                    Err(e) => error!(error = %e, "Failed to render sessions widget"),
                }
            }
            Err(e) => error!(error = %e, "Failed to fetch active sessions"),
        }

        // Update full active sessions list page (ActiveSessionsList channel)
        match fetch_active_sessions_full(&db_pool).await {
            Ok(sessions) => {
                // Send stats update
                let stats_widget = ActiveListStatsWidget {
                    sessions: sessions.clone(),
                };
                if let Ok(html) = stats_widget.render() {
                    let msg = WsMessage::new("ws-sessions-stats", html);
                    if broadcast
                        .send(&WsChannel::ActiveSessionsList, msg)
                        .await
                        .is_err()
                    {
                        trace!("No subscribers for sessions list stats channel");
                    }
                }

                // Send list content update
                let content_widget = ActiveListContentWidget { sessions };
                if let Ok(html) = content_widget.render() {
                    let msg = WsMessage::new("ws-sessions-list", html);
                    if broadcast
                        .send(&WsChannel::ActiveSessionsList, msg)
                        .await
                        .is_err()
                    {
                        trace!("No subscribers for sessions list content channel");
                    }
                }
            }
            Err(e) => error!(error = %e, "Failed to fetch active sessions for list page"),
        }
    }
}

/// Task that pushes recent activity updates.
async fn activity_updater(broadcast: Arc<BroadcastService>, db_pool: Arc<DbPool>) {
    let mut ticker = interval(Duration::from_secs(ACTIVITY_INTERVAL_SECS));

    loop {
        ticker.tick().await;

        match fetch_recent_activity(&db_pool).await {
            Ok(activities) => {
                let template = RecentActivityWidget { activities };
                match template.render() {
                    Ok(html) => {
                        let msg = WsMessage::new("ws-recent-activity", html);
                        if broadcast
                            .send(&WsChannel::RecentActivity, msg)
                            .await
                            .is_err()
                        {
                            trace!("No subscribers for activity channel");
                        }
                    }
                    Err(e) => error!(error = %e, "Failed to render activity widget"),
                }
            }
            Err(e) => error!(error = %e, "Failed to fetch recent activity"),
        }
    }
}

/// Task that pushes session list updates (for /sessions page).
async fn session_list_updater(broadcast: Arc<BroadcastService>, db_pool: Arc<DbPool>) {
    let mut ticker = interval(Duration::from_secs(SESSIONS_INTERVAL_SECS));

    loop {
        ticker.tick().await;

        match fetch_session_list(&db_pool).await {
            Ok(sessions) => {
                let widget = SessionListContentWidget {
                    sessions,
                    show_view_link: true,
                };
                if let Ok(html) = widget.render() {
                    let msg = WsMessage::new("ws-session-list-content", html);
                    if broadcast
                        .send(&WsChannel::SessionsList, msg)
                        .await
                        .is_err()
                    {
                        trace!("No subscribers for session list channel");
                    }
                }
            }
            Err(e) => error!(error = %e, "Failed to fetch session list"),
        }
    }
}

/// Fetch dashboard statistics from database.
async fn fetch_stats(db_pool: &DbPool) -> Result<StatsData, String> {
    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;

    // Count active sessions
    use crate::schema::proxy_sessions::dsl::*;
    let active_sessions_count: i64 = proxy_sessions
        .filter(status.eq("active"))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);

    // Count today's sessions
    let today_start = Utc::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .map(|dt| dt.and_utc())
        .unwrap_or_else(Utc::now);

    let today_sessions_count: i64 = proxy_sessions
        .filter(created_at.ge(today_start))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);

    // Count this week's sessions
    let week_start = Utc::now() - chrono::Duration::days(7);
    let week_sessions_count: i64 = proxy_sessions
        .filter(created_at.ge(week_start))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);

    Ok(StatsData {
        active_sessions: active_sessions_count as i32,
        today_sessions: today_sessions_count as i32,
        week_sessions: week_sessions_count as i32,
    })
}

/// Fetch active sessions from database.
async fn fetch_active_sessions(db_pool: &DbPool) -> Result<Vec<ActiveSessionItem>, String> {
    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;

    use crate::models::session::ProxySession;
    use crate::schema::proxy_sessions::dsl::*;

    let sessions: Vec<ProxySession> = proxy_sessions
        .filter(status.eq("active"))
        .order(created_at.desc())
        .limit(10)
        .load(&mut conn)
        .await
        .unwrap_or_default();

    // Calculate duration for each session
    let now = Utc::now();

    Ok(sessions
        .into_iter()
        .map(|s| {
            let duration_secs = now.signed_duration_since(s.created_at).num_seconds();
            ActiveSessionItem {
                id: s.id,
                asset_name: format!("Asset {}", s.asset_id),
                asset_hostname: s.client_ip.to_string(),
                session_type: s.session_type.to_string(),
                duration: Some(format_duration(duration_secs)),
            }
        })
        .collect())
}

/// Fetch active sessions with full details for the dedicated page.
///
/// Uses JOIN queries to resolve real usernames and asset names (not placeholders).
async fn fetch_active_sessions_full(
    db_pool: &DbPool,
) -> Result<Vec<FullActiveSessionItem>, String> {
    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;

    use crate::schema::{assets as schema_assets, proxy_sessions, users};
    use diesel::{ExpressionMethods, JoinOnDsl, QueryDsl};
    use diesel_async::RunQueryDsl;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        i32,
        uuid::Uuid,
        String,
        String,
        String,
        String,
        ipnetwork::IpNetwork,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = proxy_sessions::table
        .inner_join(schema_assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::status.eq("active"))
        .filter(proxy_sessions::connected_at.is_not_null())
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
        .load(&mut conn)
        .await
        .unwrap_or_default();

    let now = Utc::now();
    Ok(rows
        .into_iter()
        .filter_map(
            |(session_id, uuid, username, asset_name, asset_hostname, session_type, client_ip, connected_at):
             (i32, uuid::Uuid, String, String, String, String, ipnetwork::IpNetwork, Option<chrono::DateTime<chrono::Utc>>)| {
                let connected = connected_at?;
                let duration_secs = now.signed_duration_since(connected).num_seconds();
                let duration_str = format_duration(duration_secs);
                Some(FullActiveSessionItem {
                    id: session_id,
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
        .collect())
}

/// Fetch recent activity from database.
async fn fetch_recent_activity(db_pool: &DbPool) -> Result<Vec<ActivityItem>, String> {
    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;

    use crate::models::session::ProxySession;
    use crate::schema::proxy_sessions::dsl::*;

    let sessions: Vec<ProxySession> = proxy_sessions
        .order(created_at.desc())
        .limit(10)
        .load(&mut conn)
        .await
        .unwrap_or_default();

    Ok(sessions
        .into_iter()
        .map(|s| {
            let action_str = match s.session_type.as_str() {
                "ssh" => "SSH session started",
                "rdp" => "RDP session started",
                _ => "Session started",
            };
            ActivityItem {
                user: format!("User {}", s.user_id),
                action: action_str.to_string(),
                asset: Some(format!("Asset {}", s.asset_id)),
                timestamp: s.created_at,
            }
        })
        .collect())
}

/// Fetch session list for the /sessions page (admin view, page 1, no filters).
async fn fetch_session_list(db_pool: &DbPool) -> Result<Vec<SessionListItem>, String> {
    use crate::schema::{assets as schema_assets, proxy_sessions};

    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;

    const SESSIONS_PER_PAGE: i64 = 30;

    #[allow(clippy::type_complexity)]
    let db_sessions: Vec<(
        i32,
        uuid::Uuid,
        String,
        String,
        crate::models::session::SessionType,
        String,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        bool,
    )> = proxy_sessions::table
        .inner_join(schema_assets::table)
        .filter(proxy_sessions::status.ne("pending"))
        .filter(proxy_sessions::status.ne("orphaned"))
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
        .limit(SESSIONS_PER_PAGE)
        .load(&mut conn)
        .await
        .unwrap_or_default();

    let now = Utc::now();
    Ok(db_sessions
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
                    (Some(start), None) if status == "active" => {
                        Some(now.signed_duration_since(start).num_seconds())
                    }
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
                    connected_at: connected_at
                        .map(|dt| dt.format("%b %d, %Y %H:%M").to_string()),
                    duration_seconds,
                    is_recorded,
                }
            },
        )
        .collect())
}

/// Push an immediate session list update to all subscribers.
///
/// Called by handlers (e.g. terminate_session) to trigger an instant
/// refresh of the /sessions page without waiting for the next polling cycle.
pub async fn push_session_list_update(broadcast: &BroadcastService, db_pool: &DbPool) {
    match fetch_session_list(db_pool).await {
        Ok(sessions) => {
            let widget = SessionListContentWidget {
                sessions,
                show_view_link: true,
            };
            if let Ok(html) = widget.render() {
                let msg = WsMessage::new("ws-session-list-content", html);
                let _ = broadcast.send(&WsChannel::SessionsList, msg).await;
            }
        }
        Err(e) => error!(error = %e, "Failed to push session list update"),
    }
}

/// Push an immediate active sessions update to all subscribers.
///
/// Called by handlers (e.g. terminate_session) to trigger an instant
/// refresh of the /sessions/active page without waiting for the next polling cycle.
pub async fn push_active_sessions_update(broadcast: &BroadcastService, db_pool: &DbPool) {
    match fetch_active_sessions_full(db_pool).await {
        Ok(sessions) => {
            let stats_widget = ActiveListStatsWidget {
                sessions: sessions.clone(),
            };
            if let Ok(html) = stats_widget.render() {
                let msg = WsMessage::new("ws-sessions-stats", html);
                let _ = broadcast
                    .send(&WsChannel::ActiveSessionsList, msg)
                    .await;
            }

            let content_widget = ActiveListContentWidget { sessions };
            if let Ok(html) = content_widget.render() {
                let msg = WsMessage::new("ws-sessions-list", html);
                let _ = broadcast
                    .send(&WsChannel::ActiveSessionsList, msg)
                    .await;
            }
        }
        Err(e) => error!(error = %e, "Failed to push active sessions update"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Interval Constants Tests ====================

    #[test]
    fn test_stats_interval() {
        assert_eq!(STATS_INTERVAL_SECS, 30);
    }

    #[test]
    fn test_sessions_interval() {
        assert_eq!(SESSIONS_INTERVAL_SECS, 10);
    }

    #[test]
    fn test_activity_interval() {
        assert_eq!(ACTIVITY_INTERVAL_SECS, 30);
    }

    #[test]
    fn test_stats_interval_is_reasonable() {
        assert!((5..=60).contains(&STATS_INTERVAL_SECS));
    }

    #[test]
    #[allow(clippy::assertions_on_constants)] // invariant: sessions poll (10s) faster than stats (30s)
    fn test_sessions_interval_is_faster_than_stats() {
        assert!(SESSIONS_INTERVAL_SECS < STATS_INTERVAL_SECS);
    }

    // ==================== Duration Tests ====================

    #[test]
    fn test_duration_from_stats_interval() {
        let duration = Duration::from_secs(STATS_INTERVAL_SECS);
        assert_eq!(duration.as_secs(), 30);
    }

    #[test]
    fn test_duration_from_sessions_interval() {
        let duration = Duration::from_secs(SESSIONS_INTERVAL_SECS);
        assert_eq!(duration.as_secs(), 10);
    }

    #[test]
    fn test_duration_from_activity_interval() {
        let duration = Duration::from_secs(ACTIVITY_INTERVAL_SECS);
        assert_eq!(duration.as_secs(), 30);
    }

    // ==================== Interval Creation Tests ====================

    #[tokio::test]
    async fn test_interval_creation() {
        let mut ticker = interval(Duration::from_secs(STATS_INTERVAL_SECS));
        // First tick is immediate
        ticker.tick().await;
        assert_eq!(ticker.period(), Duration::from_secs(STATS_INTERVAL_SECS));
    }

    #[test]
    fn test_stats_interval_as_millis() {
        let duration = Duration::from_secs(STATS_INTERVAL_SECS);
        assert_eq!(duration.as_millis(), 30000);
    }

    #[test]
    fn test_sessions_interval_as_millis() {
        let duration = Duration::from_secs(SESSIONS_INTERVAL_SECS);
        assert_eq!(duration.as_millis(), 10000);
    }

    // ==================== Interval Comparison Tests ====================

    #[test]
    fn test_activity_interval_equals_stats_interval() {
        assert_eq!(ACTIVITY_INTERVAL_SECS, STATS_INTERVAL_SECS);
    }

    #[test]
    fn test_all_intervals_nonzero() {
        assert_ne!(STATS_INTERVAL_SECS, 0);
        assert_ne!(SESSIONS_INTERVAL_SECS, 0);
        assert_ne!(ACTIVITY_INTERVAL_SECS, 0);
    }

    #[test]
    fn test_intervals_are_multiples_of_5() {
        // Good practice for dashboard updates
        assert_eq!(STATS_INTERVAL_SECS % 5, 0);
        assert_eq!(SESSIONS_INTERVAL_SECS % 5, 0);
        assert_eq!(ACTIVITY_INTERVAL_SECS % 5, 0);
    }

    // ==================== Arc/Clone Pattern Tests ====================

    #[test]
    fn test_arc_clone_pattern() {
        // Test that the Arc pattern used in start_dashboard_tasks works
        let broadcast = BroadcastService::new();
        let broadcast_arc = Arc::new(broadcast);
        let cloned = Arc::clone(&broadcast_arc);

        // Both should point to the same allocation
        assert!(Arc::ptr_eq(&broadcast_arc, &cloned));
    }

    #[test]
    fn test_duration_conversion() {
        // Verify durations can be converted correctly
        let secs = STATS_INTERVAL_SECS;
        let duration = Duration::from_secs(secs);
        assert_eq!(duration.as_secs(), secs);
    }

    // ==================== Session List Updater Structural Tests ====================

    #[test]
    fn test_session_list_updater_exists() {
        let source = include_str!("dashboard.rs");
        assert!(
            source.contains("fn session_list_updater"),
            "session_list_updater task must exist"
        );
    }

    #[test]
    fn test_session_list_updater_uses_sessions_list_channel() {
        let source = include_str!("dashboard.rs");
        assert!(
            source.contains("WsChannel::SessionsList"),
            "session_list_updater must broadcast to SessionsList channel"
        );
    }

    #[test]
    fn test_push_session_list_update_exists() {
        let source = include_str!("dashboard.rs");
        assert!(
            source.contains("pub async fn push_session_list_update"),
            "push_session_list_update must be public for use by handlers"
        );
    }

    #[test]
    fn test_session_list_updater_target_id() {
        let source = include_str!("dashboard.rs");
        assert!(
            source.contains("ws-session-list-content"),
            "session_list_updater must target ws-session-list-content div"
        );
    }

    // ==================== Active Sessions Full Fetch Structural Tests ====================

    #[test]
    fn test_fetch_active_sessions_full_uses_join() {
        let source = include_str!("dashboard.rs");
        let fn_start = source
            .find("fn fetch_active_sessions_full")
            .expect("fetch_active_sessions_full must exist");
        let fn_body = &source[fn_start..];
        let next_fn = fn_body[1..]
            .find("\nasync fn ")
            .or_else(|| fn_body[1..].find("\nfn "))
            .or_else(|| fn_body[1..].find("#[cfg(test)]"))
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..next_fn];

        assert!(
            fn_body.contains("inner_join(schema_assets::table)"),
            "fetch_active_sessions_full must join assets table"
        );
        assert!(
            fn_body.contains("inner_join(users::table"),
            "fetch_active_sessions_full must join users table"
        );
    }

    #[test]
    fn test_fetch_active_sessions_full_no_mock_data() {
        let source = include_str!("dashboard.rs");
        let fn_start = source
            .find("fn fetch_active_sessions_full")
            .expect("fetch_active_sessions_full must exist");
        let fn_body = &source[fn_start..];
        let next_fn = fn_body[1..]
            .find("\nasync fn ")
            .or_else(|| fn_body[1..].find("\nfn "))
            .or_else(|| fn_body[1..].find("#[cfg(test)]"))
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..next_fn];

        assert!(
            !fn_body.contains("format!(\"User"),
            "fetch_active_sessions_full must not use mock User placeholders"
        );
        assert!(
            !fn_body.contains("format!(\"Asset"),
            "fetch_active_sessions_full must not use mock Asset placeholders"
        );
    }

    #[test]
    fn test_fetch_active_sessions_full_filters_connected_at() {
        let source = include_str!("dashboard.rs");
        let fn_start = source
            .find("fn fetch_active_sessions_full")
            .expect("fetch_active_sessions_full must exist");
        let fn_body = &source[fn_start..];
        let next_fn = fn_body[1..]
            .find("\nasync fn ")
            .or_else(|| fn_body[1..].find("\nfn "))
            .or_else(|| fn_body[1..].find("#[cfg(test)]"))
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..next_fn];

        assert!(
            fn_body.contains("connected_at.is_not_null()"),
            "fetch_active_sessions_full must filter on connected_at IS NOT NULL"
        );
    }

    #[test]
    fn test_fetch_active_sessions_full_orders_by_connected_at() {
        let source = include_str!("dashboard.rs");
        let fn_start = source
            .find("fn fetch_active_sessions_full")
            .expect("fetch_active_sessions_full must exist");
        let fn_body = &source[fn_start..];
        let next_fn = fn_body[1..]
            .find("\nasync fn ")
            .or_else(|| fn_body[1..].find("\nfn "))
            .or_else(|| fn_body[1..].find("#[cfg(test)]"))
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..next_fn];

        assert!(
            fn_body.contains("connected_at.desc()"),
            "fetch_active_sessions_full must order by connected_at desc"
        );
    }

    #[test]
    fn test_push_active_sessions_update_exists() {
        let source = include_str!("dashboard.rs");
        assert!(
            source.contains("pub async fn push_active_sessions_update"),
            "push_active_sessions_update must be public for use by handlers"
        );
    }

    #[test]
    fn test_push_active_sessions_update_uses_correct_target_ids() {
        let source = include_str!("dashboard.rs");
        let fn_start = source
            .find("fn push_active_sessions_update")
            .expect("push_active_sessions_update must exist");
        let fn_body = &source[fn_start..];
        let next_fn = fn_body[1..]
            .find("\npub async fn ")
            .or_else(|| fn_body[1..].find("\nasync fn "))
            .or_else(|| fn_body[1..].find("#[cfg(test)]"))
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..next_fn];

        assert!(
            fn_body.contains("ws-sessions-stats"),
            "push_active_sessions_update must target ws-sessions-stats"
        );
        assert!(
            fn_body.contains("ws-sessions-list"),
            "push_active_sessions_update must target ws-sessions-list"
        );
    }
}
