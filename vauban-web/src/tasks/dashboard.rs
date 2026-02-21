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
async fn fetch_active_sessions_full(
    db_pool: &DbPool,
) -> Result<Vec<FullActiveSessionItem>, String> {
    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;

    use crate::models::session::ProxySession;
    use crate::schema::proxy_sessions::dsl::*;

    let sessions: Vec<ProxySession> = proxy_sessions
        .filter(status.eq("active"))
        .order(created_at.desc())
        .load(&mut conn)
        .await
        .unwrap_or_default();

    let now = Utc::now();
    Ok(sessions
        .into_iter()
        .map(|s| {
            let duration_secs = now.signed_duration_since(s.created_at).num_seconds();
            let duration_str = format_duration(duration_secs);
            FullActiveSessionItem {
                uuid: s.uuid.to_string(),
                username: format!("User {}", s.user_id),
                asset_name: format!("Asset {}", s.asset_id),
                asset_hostname: s.client_ip.to_string(),
                session_type: s.session_type.to_string(),
                client_ip: s.client_ip.to_string(),
                connected_at: s.created_at.format("%Y-%m-%d %H:%M").to_string(),
                duration: duration_str,
            }
        })
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
                "vnc" => "VNC session started",
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
        // Stats should update at least every minute
        assert!(STATS_INTERVAL_SECS <= 60);
        assert!(STATS_INTERVAL_SECS >= 5);
    }

    #[test]
    fn test_sessions_interval_is_faster_than_stats() {
        // Active sessions should update more frequently than stats
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
        // Verify the interval was created successfully
        assert!(true);
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
        assert!(STATS_INTERVAL_SECS > 0);
        assert!(SESSIONS_INTERVAL_SECS > 0);
        assert!(ACTIVITY_INTERVAL_SECS > 0);
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
}
