use askama::Template;
use axum::{
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
/// VAUBAN Web - WebSocket handlers.
///
/// Handles WebSocket connections for real-time updates.
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::AppState;
use crate::db::get_connection;
use crate::middleware::auth::AuthUser;
use crate::services::broadcast::WsChannel;

/// Ping interval to keep WebSocket connection alive.
const PING_INTERVAL_SECS: u64 = 30;

/// Dashboard WebSocket handler.
///
/// Establishes a WebSocket connection for dashboard widgets.
/// Subscribes to: stats, active-sessions, recent-activity.
pub async fn dashboard_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    user: AuthUser,
) -> impl IntoResponse {
    info!(user = %user.username, "Dashboard WebSocket connection requested");
    ws.on_upgrade(move |socket| handle_dashboard_socket(socket, state, user))
}

/// Handle dashboard WebSocket connection.
async fn handle_dashboard_socket(socket: WebSocket, state: AppState, user: AuthUser) {
    let (mut sender, mut receiver) = socket.split();

    info!(user = %user.username, "Dashboard WebSocket connected");

    // Send initial data immediately on connection
    if let Err(e) = send_initial_dashboard_data(&mut sender, &state).await {
        error!(user = %user.username, error = %e, "Failed to send initial data");
        return;
    }
    debug!(user = %user.username, "Initial dashboard data sent");

    // Subscribe to dashboard channels for future updates
    let mut stats_rx = state.broadcast.subscribe(&WsChannel::DashboardStats).await;
    let mut sessions_rx = state.broadcast.subscribe(&WsChannel::ActiveSessions).await;
    let mut activity_rx = state.broadcast.subscribe(&WsChannel::RecentActivity).await;
    let mut notifications_rx = state.broadcast.subscribe(&WsChannel::Notifications).await;

    // Create ping interval to keep connection alive
    let mut ping_interval = interval(Duration::from_secs(PING_INTERVAL_SECS));

    // Flag to track if connection should close
    let mut should_close = false;

    // Main loop: handle incoming messages, broadcast updates, and keep-alive pings
    loop {
        tokio::select! {
            // Handle incoming messages from client
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        debug!(user = %user.username, message = %text, "Received WS text message");
                    }
                    Some(Ok(Message::Ping(_))) => {
                        debug!(user = %user.username, "Received WS ping");
                        // Pong is sent automatically by axum
                    }
                    Some(Ok(Message::Pong(_))) => {
                        debug!(user = %user.username, "Received WS pong");
                    }
                    Some(Ok(Message::Close(_))) => {
                        info!(user = %user.username, "Client requested close");
                        should_close = true;
                    }
                    Some(Err(e)) => {
                        error!(user = %user.username, error = %e, "WebSocket error");
                        should_close = true;
                    }
                    None => {
                        info!(user = %user.username, "WebSocket stream ended");
                        should_close = true;
                    }
                    _ => {}
                }
            }

            // Send periodic ping to keep connection alive
            _ = ping_interval.tick() => {
                if sender.send(Message::Ping(vec![].into())).await.is_err() {
                    warn!(user = %user.username, "Failed to send ping, closing");
                    should_close = true;
                } else {
                    debug!(user = %user.username, "Sent WS ping");
                }
            }

            // Stats channel updates
            result = stats_rx.recv() => {
                if let Ok(html) = result {
                    if sender.send(Message::Text(html.into())).await.is_err() {
                        should_close = true;
                    }
                }
            }

            // Active sessions channel updates
            result = sessions_rx.recv() => {
                if let Ok(html) = result {
                    if sender.send(Message::Text(html.into())).await.is_err() {
                        should_close = true;
                    }
                }
            }

            // Recent activity channel updates
            result = activity_rx.recv() => {
                if let Ok(html) = result {
                    if sender.send(Message::Text(html.into())).await.is_err() {
                        should_close = true;
                    }
                }
            }

            // Notifications channel updates
            result = notifications_rx.recv() => {
                if let Ok(html) = result {
                    if sender.send(Message::Text(html.into())).await.is_err() {
                        should_close = true;
                    }
                }
            }
        }

        if should_close {
            break;
        }
    }

    info!(user = %user.username, "Dashboard WebSocket disconnected");
}

/// Send initial dashboard data immediately on WebSocket connection.
async fn send_initial_dashboard_data(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    state: &AppState,
) -> Result<(), String> {
    use crate::services::broadcast::WsMessage;
    use crate::templates::dashboard::widgets::{
        ActiveSessionsWidget, RecentActivityWidget, StatsWidget,
    };

    // Fetch and send stats
    let stats = fetch_initial_stats(state)?;
    let stats_widget = StatsWidget { stats };
    if let Ok(html) = stats_widget.render() {
        let msg = WsMessage::new("ws-stats", html);
        sender
            .send(Message::Text(msg.to_htmx_html().into()))
            .await
            .map_err(|e| e.to_string())?;
    }

    // Fetch and send active sessions
    let sessions = fetch_initial_sessions(state)?;
    let sessions_widget = ActiveSessionsWidget { sessions };
    if let Ok(html) = sessions_widget.render() {
        let msg = WsMessage::new("ws-active-sessions", html);
        sender
            .send(Message::Text(msg.to_htmx_html().into()))
            .await
            .map_err(|e| e.to_string())?;
    }

    // Fetch and send recent activity
    let activities = fetch_initial_activity(state)?;
    let activity_widget = RecentActivityWidget { activities };
    if let Ok(html) = activity_widget.render() {
        let msg = WsMessage::new("ws-recent-activity", html);
        sender
            .send(Message::Text(msg.to_htmx_html().into()))
            .await
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}

/// Fetch initial stats data.
fn fetch_initial_stats(
    state: &AppState,
) -> Result<crate::templates::dashboard::widgets::StatsData, String> {
    use crate::templates::dashboard::widgets::StatsData;
    use chrono::Utc;
    use diesel::prelude::*;

    let mut conn = get_connection(&state.db_pool).map_err(|e| e.to_string())?;

    use crate::schema::proxy_sessions::dsl::*;

    let active_count: i64 = proxy_sessions
        .filter(status.eq("active"))
        .count()
        .get_result(&mut conn)
        .unwrap_or(0);

    let today_start = Utc::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .map(|dt| dt.and_utc())
        .unwrap_or_else(Utc::now);

    let today_count: i64 = proxy_sessions
        .filter(created_at.ge(today_start))
        .count()
        .get_result(&mut conn)
        .unwrap_or(0);

    let week_start = Utc::now() - chrono::Duration::days(7);
    let week_count: i64 = proxy_sessions
        .filter(created_at.ge(week_start))
        .count()
        .get_result(&mut conn)
        .unwrap_or(0);

    Ok(StatsData {
        active_sessions: active_count as i32,
        today_sessions: today_count as i32,
        week_sessions: week_count as i32,
    })
}

/// Fetch initial active sessions.
fn fetch_initial_sessions(
    state: &AppState,
) -> Result<Vec<crate::templates::dashboard::widgets::ActiveSessionItem>, String> {
    use crate::models::session::ProxySession;
    use crate::templates::dashboard::widgets::ActiveSessionItem;
    use chrono::Utc;
    use diesel::prelude::*;

    let mut conn = get_connection(&state.db_pool).map_err(|e| e.to_string())?;

    use crate::schema::proxy_sessions::dsl::*;

    let sessions: Vec<ProxySession> = proxy_sessions
        .filter(status.eq("active"))
        .order(created_at.desc())
        .limit(10)
        .load(&mut conn)
        .unwrap_or_default();

    let now = Utc::now();
    Ok(sessions
        .into_iter()
        .map(|s| {
            let duration = now.signed_duration_since(s.created_at).num_seconds();
            ActiveSessionItem {
                id: s.id,
                asset_name: format!("Asset {}", s.asset_id),
                asset_hostname: s.client_ip.to_string(),
                session_type: s.session_type,
                duration_seconds: Some(duration),
            }
        })
        .collect())
}

/// Fetch initial recent activity.
fn fetch_initial_activity(
    state: &AppState,
) -> Result<Vec<crate::templates::dashboard::widgets::ActivityItem>, String> {
    use crate::models::session::ProxySession;
    use crate::templates::dashboard::widgets::ActivityItem;
    use diesel::prelude::*;

    let mut conn = get_connection(&state.db_pool).map_err(|e| e.to_string())?;

    use crate::schema::proxy_sessions::dsl::*;

    let sessions: Vec<ProxySession> = proxy_sessions
        .order(created_at.desc())
        .limit(10)
        .load(&mut conn)
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

/// Session live WebSocket handler.
///
/// Establishes a WebSocket connection for live session updates.
pub async fn session_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    user: AuthUser,
) -> impl IntoResponse {
    info!(
        user = %user.username,
        session_id = %session_id,
        "Session WebSocket connection requested"
    );
    ws.on_upgrade(move |socket| handle_session_socket(socket, state, session_id, user))
}

/// Handle session WebSocket connection.
async fn handle_session_socket(
    socket: WebSocket,
    state: AppState,
    session_id: String,
    user: AuthUser,
) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to session-specific channel
    let channel = WsChannel::SessionLive(session_id.clone());
    let mut session_rx = state.broadcast.subscribe(&channel).await;

    info!(
        user = %user.username,
        session_id = %session_id,
        "Session WebSocket connected"
    );

    // Handle incoming messages
    let user_clone = user.clone();
    let session_id_clone = session_id.clone();
    let incoming_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    debug!(
                        user = %user_clone.username,
                        session_id = %session_id_clone,
                        message = %text,
                        "Received session WS message"
                    );
                }
                Ok(Message::Close(_)) => {
                    info!(
                        user = %user_clone.username,
                        session_id = %session_id_clone,
                        "Session WS close requested"
                    );
                    break;
                }
                Err(e) => {
                    error!(
                        user = %user_clone.username,
                        session_id = %session_id_clone,
                        error = %e,
                        "Session WebSocket error"
                    );
                    break;
                }
                _ => {}
            }
        }
    });

    // Forward session updates to client
    loop {
        match session_rx.recv().await {
            Ok(html) => {
                if sender.send(Message::Text(html.into())).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "Session channel lagged"
                );
            }
        }
    }

    // Cleanup
    incoming_task.abort();
    info!(
        user = %user.username,
        session_id = %session_id,
        "Session WebSocket disconnected"
    );
}

/// Notifications WebSocket handler.
///
/// Establishes a WebSocket connection for user notifications only.
pub async fn notifications_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    user: AuthUser,
) -> impl IntoResponse {
    info!(user = %user.username, "Notifications WebSocket connection requested");
    ws.on_upgrade(move |socket| handle_notifications_socket(socket, state, user))
}

/// Handle notifications WebSocket connection.
async fn handle_notifications_socket(socket: WebSocket, state: AppState, user: AuthUser) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to notifications channel
    let mut notifications_rx = state.broadcast.subscribe(&WsChannel::Notifications).await;

    info!(user = %user.username, "Notifications WebSocket connected");

    // Handle incoming messages
    let user_clone = user.clone();
    let incoming_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Close(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
        debug!(user = %user_clone.username, "Notifications incoming handler done");
    });

    // Forward notifications to client
    loop {
        match notifications_rx.recv().await {
            Ok(html) => {
                if sender.send(Message::Text(html.into())).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                warn!(error = %e, "Notifications channel lagged");
            }
        }
    }

    incoming_task.abort();
    info!(user = %user.username, "Notifications WebSocket disconnected");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_channel_session_live() {
        let channel = WsChannel::SessionLive("test-123".to_string());
        assert_eq!(channel.as_str(), "session:test-123");
    }

    #[test]
    fn test_ws_channel_dashboard_stats() {
        let channel = WsChannel::DashboardStats;
        assert_eq!(channel.as_str(), "dashboard:stats");
    }
}
