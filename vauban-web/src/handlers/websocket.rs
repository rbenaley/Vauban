use askama::Template;
use axum::{
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
};
use axum_extra::extract::CookieJar;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sha3::{Digest, Sha3_256};
/// VAUBAN Web - WebSocket handlers.
///
/// Handles WebSocket connections for real-time updates.
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::utils::format_duration;

use crate::AppState;
use crate::middleware::auth::AuthUser;
use crate::services::broadcast::WsChannel;

/// Verify that a proxy session exists and belongs to the authenticated user.
///
/// Returns `Ok(())` if:
/// - The session exists in the database with the given UUID
/// - The session's `user_id` matches the authenticated user's UUID
/// - OR the user is staff/superuser (admin monitoring)
///
/// Returns `Err(StatusCode)` otherwise.
async fn verify_session_ownership(
    state: &AppState,
    session_uuid_str: &str,
    user: &AuthUser,
) -> Result<(), axum::http::StatusCode> {
    use crate::schema::{proxy_sessions, users};
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;

    // Parse the session UUID
    let session_uuid: uuid::Uuid = session_uuid_str
        .parse()
        .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

    // Parse the authenticated user's UUID
    let user_uuid: uuid::Uuid = user
        .uuid
        .parse()
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    // Query: join proxy_sessions with users to check ownership via UUID
    let owner_uuid: Option<uuid::Uuid> = proxy_sessions::table
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .select(users::uuid)
        .first(&mut conn)
        .await
        .optional()
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    match owner_uuid {
        None => {
            // Session not found
            warn!(
                session_id = %session_uuid_str,
                user = %user.username,
                "WebSocket rejected: session not found"
            );
            Err(axum::http::StatusCode::NOT_FOUND)
        }
        Some(owner) if owner == user_uuid || user.is_staff || user.is_superuser => {
            // Session belongs to user, or user is admin
            Ok(())
        }
        Some(_) => {
            // Session belongs to another user and requester is not admin
            warn!(
                session_id = %session_uuid_str,
                user = %user.username,
                "WebSocket rejected: session belongs to another user"
            );
            Err(axum::http::StatusCode::FORBIDDEN)
        }
    }
}

/// Middleware guard for session-specific WebSocket routes.
///
/// Extracts the session ID from the last URI path segment and verifies
/// that the authenticated user owns the session (or is staff/superuser).
///
/// This middleware MUST run before the WebSocket handler so that
/// ownership is checked before the WebSocket upgrade extractor.
pub async fn ws_session_guard(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Extract AuthUser from request extensions (set by auth middleware)
    let user = match request.extensions().get::<AuthUser>() {
        Some(user) => user.clone(),
        None => {
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
    };

    // Extract session ID from the last path segment
    // Routes: /ws/terminal/{session_id} and /ws/session/{id}
    let path = request.uri().path().to_string();
    let session_id = path.rsplit('/').next().unwrap_or("");

    match verify_session_ownership(&state, session_id, &user).await {
        Err(status) => status.into_response(),
        Ok(()) => next.run(request).await,
    }
}

/// Terminal control commands received from the frontend.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum TerminalCommand {
    /// Resize the terminal PTY.
    Resize {
        cols: u16,
        rows: u16,
    },
    /// Explicit data to send to terminal (alternative to raw text).
    Data {
        data: String,
    },
}

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
                if let Ok(html) = result
                    && sender.send(Message::Text(html.into())).await.is_err()
                {
                    should_close = true;
                }
            }

            // Active sessions channel updates
            result = sessions_rx.recv() => {
                if let Ok(html) = result
                    && sender.send(Message::Text(html.into())).await.is_err()
                {
                    should_close = true;
                }
            }

            // Recent activity channel updates
            result = activity_rx.recv() => {
                if let Ok(html) = result
                    && sender.send(Message::Text(html.into())).await.is_err()
                {
                    should_close = true;
                }
            }

            // Notifications channel updates
            result = notifications_rx.recv() => {
                if let Ok(html) = result
                    && sender.send(Message::Text(html.into())).await.is_err()
                {
                    should_close = true;
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
    let stats = fetch_initial_stats(state).await?;
    let stats_widget = StatsWidget { stats };
    if let Ok(html) = stats_widget.render() {
        let msg = WsMessage::new("ws-stats", html);
        sender
            .send(Message::Text(msg.to_htmx_html().into()))
            .await
            .map_err(|e| e.to_string())?;
    }

    // Fetch and send active sessions
    let sessions = fetch_initial_sessions(state).await?;
    let sessions_widget = ActiveSessionsWidget { sessions };
    if let Ok(html) = sessions_widget.render() {
        let msg = WsMessage::new("ws-active-sessions", html);
        sender
            .send(Message::Text(msg.to_htmx_html().into()))
            .await
            .map_err(|e| e.to_string())?;
    }

    // Fetch and send recent activity
    let activities = fetch_initial_activity(state).await?;
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
async fn fetch_initial_stats(
    state: &AppState,
) -> Result<crate::templates::dashboard::widgets::StatsData, String> {
    use crate::templates::dashboard::widgets::StatsData;
    use chrono::Utc;
    use diesel::{ExpressionMethods, QueryDsl};
    use diesel_async::RunQueryDsl;

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;

    use crate::schema::proxy_sessions::dsl::*;

    let active_count: i64 = proxy_sessions
        .filter(status.eq("active"))
        .count()
        .get_result(&mut conn)
        .await
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
        .await
        .unwrap_or(0);

    let week_start = Utc::now() - chrono::Duration::days(7);
    let week_count: i64 = proxy_sessions
        .filter(created_at.ge(week_start))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);

    Ok(StatsData {
        active_sessions: active_count as i32,
        today_sessions: today_count as i32,
        week_sessions: week_count as i32,
    })
}

/// Fetch initial active sessions.
async fn fetch_initial_sessions(
    state: &AppState,
) -> Result<Vec<crate::templates::dashboard::widgets::ActiveSessionItem>, String> {
    use crate::models::session::ProxySession;
    use crate::templates::dashboard::widgets::ActiveSessionItem;
    use chrono::Utc;
    use diesel::{ExpressionMethods, QueryDsl};
    use diesel_async::RunQueryDsl;

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;

    use crate::schema::proxy_sessions::dsl::*;

    let sessions: Vec<ProxySession> = proxy_sessions
        .filter(status.eq("active"))
        .order(created_at.desc())
        .limit(10)
        .load(&mut conn)
        .await
        .unwrap_or_default();

    let now = Utc::now();
    Ok(sessions
        .into_iter()
        .map(|s| {
            let duration_secs = now.signed_duration_since(s.created_at).num_seconds();
            ActiveSessionItem {
                id: s.id,
                asset_name: format!("Asset {}", s.asset_id),
                asset_hostname: s.client_ip.to_string(),
                session_type: s.session_type,
                duration: Some(format_duration(duration_secs)),
            }
        })
        .collect())
}

/// Fetch initial recent activity.
async fn fetch_initial_activity(
    state: &AppState,
) -> Result<Vec<crate::templates::dashboard::widgets::ActivityItem>, String> {
    use crate::models::session::ProxySession;
    use crate::templates::dashboard::widgets::ActivityItem;
    use diesel::{ExpressionMethods, QueryDsl};
    use diesel_async::RunQueryDsl;

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;

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

/// Session live WebSocket handler.
///
/// Establishes a WebSocket connection for live session updates.
///
/// Security: Session ownership is verified by the `ws_session_guard` middleware
/// before this handler is called. Only the session owner or staff/superuser
/// users can reach this handler.
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
/// Extracts the access_token cookie to compute token_hash for personalized messages.
pub async fn notifications_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    jar: CookieJar,
    user: AuthUser,
) -> impl IntoResponse {
    info!(user = %user.username, "Notifications WebSocket connection requested");

    // Compute token_hash from access_token cookie for personalized session identification
    let token_hash = jar
        .get("access_token")
        .map(|cookie| {
            let mut hasher = Sha3_256::new();
            hasher.update(cookie.value().as_bytes());
            format!("{:x}", hasher.finalize())
        })
        .unwrap_or_default();

    ws.on_upgrade(move |socket| handle_notifications_socket(socket, state, user, token_hash))
}

/// Handle notifications WebSocket connection.
/// Subscribes to user-specific channels for auth sessions and API keys updates.
/// Also registers with UserConnectionRegistry for personalized session updates.
async fn handle_notifications_socket(
    socket: WebSocket,
    state: AppState,
    user: AuthUser,
    token_hash: String,
) {
    let (mut sender, mut receiver) = socket.split();

    // Register this connection for personalized auth session updates
    let (connection_id, mut personalized_rx) = state
        .user_connections
        .register(&user.uuid, token_hash)
        .await;

    // Subscribe to broadcast channels for other updates
    let mut notifications_rx = state.broadcast.subscribe(&WsChannel::Notifications).await;
    let mut api_keys_rx = state
        .broadcast
        .subscribe(&WsChannel::UserApiKeys(user.uuid.clone()))
        .await;

    info!(
        user = %user.username,
        user_uuid = %user.uuid,
        connection_id = %connection_id,
        "Notifications WebSocket connected with personalized session support"
    );

    // Create ping interval to keep connection alive
    let mut ping_interval = interval(Duration::from_secs(PING_INTERVAL_SECS));
    let mut should_close = false;

    loop {
        tokio::select! {
            // Handle incoming messages from client
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) => {
                        debug!(user = %user.username, "Client requested close");
                        should_close = true;
                    }
                    Some(Err(e)) => {
                        error!(user = %user.username, error = %e, "WebSocket error");
                        should_close = true;
                    }
                    None => {
                        debug!(user = %user.username, "WebSocket stream ended");
                        should_close = true;
                    }
                    _ => {}
                }
            }

            // Send periodic ping to keep connection alive
            _ = ping_interval.tick() => {
                if sender.send(Message::Ping(vec![].into())).await.is_err() {
                    should_close = true;
                }
            }

            // General notifications channel
            result = notifications_rx.recv() => {
                if let Ok(html) = result
                    && sender.send(Message::Text(html.into())).await.is_err()
                {
                    should_close = true;
                }
            }

            // Personalized auth sessions updates (from UserConnectionRegistry)
            Some(html) = personalized_rx.recv() => {
                debug!(user = %user.username, "Sending personalized auth sessions update");
                if sender.send(Message::Text(html.into())).await.is_err() {
                    should_close = true;
                }
            }

            // User API keys channel (for /accounts/apikeys page)
            result = api_keys_rx.recv() => {
                if let Ok(html) = result {
                    debug!(user = %user.username, "Sending API keys update");
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

    // Unregister this connection
    state
        .user_connections
        .unregister(&user.uuid, connection_id)
        .await;

    info!(
        user = %user.username,
        connection_id = %connection_id,
        "Notifications WebSocket disconnected"
    );
}

/// Active sessions list WebSocket handler.
///
/// Establishes a WebSocket connection for real-time active sessions list updates.
/// Used by the /sessions/active page.
pub async fn active_sessions_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    user: AuthUser,
) -> impl IntoResponse {
    info!(user = %user.username, "Active sessions list WebSocket connection requested");
    ws.on_upgrade(move |socket| handle_active_sessions_socket(socket, state, user))
}

/// Handle active sessions list WebSocket connection.
async fn handle_active_sessions_socket(socket: WebSocket, state: AppState, user: AuthUser) {
    let (mut sender, mut receiver) = socket.split();

    info!(user = %user.username, "Active sessions list WebSocket connected");

    // Send initial data immediately on connection
    if let Err(e) = send_initial_active_sessions_data(&mut sender, &state).await {
        error!(user = %user.username, error = %e, "Failed to send initial active sessions data");
        return;
    }
    debug!(user = %user.username, "Initial active sessions data sent");

    // Subscribe to active sessions list channel for future updates
    let mut sessions_rx = state
        .broadcast
        .subscribe(&WsChannel::ActiveSessionsList)
        .await;

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

            // Active sessions list channel updates
            result = sessions_rx.recv() => {
                if let Ok(html) = result
                    && sender.send(Message::Text(html.into())).await.is_err()
                {
                    should_close = true;
                }
            }
        }

        if should_close {
            break;
        }
    }

    info!(user = %user.username, "Active sessions list WebSocket disconnected");
}

/// Send initial active sessions data immediately on WebSocket connection.
async fn send_initial_active_sessions_data(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    state: &AppState,
) -> Result<(), String> {
    use crate::services::broadcast::WsMessage;
    use crate::templates::sessions::{ActiveListContentWidget, ActiveListStatsWidget};

    // Fetch active sessions
    let sessions = fetch_active_sessions_list(state).await?;

    // Send stats widget
    let stats_widget = ActiveListStatsWidget {
        sessions: sessions.clone(),
    };
    if let Ok(html) = stats_widget.render() {
        let msg = WsMessage::new("ws-sessions-stats", html);
        sender
            .send(Message::Text(msg.to_htmx_html().into()))
            .await
            .map_err(|e| e.to_string())?;
    }

    // Send sessions list content
    let content_widget = ActiveListContentWidget { sessions };
    if let Ok(html) = content_widget.render() {
        let msg = WsMessage::new("ws-sessions-list", html);
        sender
            .send(Message::Text(msg.to_htmx_html().into()))
            .await
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}

/// Fetch active sessions list for the dedicated page.
async fn fetch_active_sessions_list(
    state: &AppState,
) -> Result<Vec<crate::templates::sessions::ActiveSessionItem>, String> {
    use crate::models::session::ProxySession;
    use crate::templates::sessions::ActiveSessionItem;
    use chrono::Utc;
    use diesel::{ExpressionMethods, QueryDsl};
    use diesel_async::RunQueryDsl;

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;

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
            ActiveSessionItem {
                uuid: s.uuid.to_string(),
                username: format!("User {}", s.user_id),
                asset_name: format!("Asset {}", s.asset_id),
                asset_hostname: s.client_ip.to_string(),
                session_type: s.session_type.clone(),
                client_ip: s.client_ip.to_string(),
                connected_at: s.created_at.format("%Y-%m-%d %H:%M").to_string(),
                duration: duration_str,
            }
        })
        .collect())
}

/// Terminal WebSocket handler for SSH sessions.
///
/// Establishes a bidirectional WebSocket connection for interactive SSH terminal.
/// Receives terminal input from client, forwards to SSH proxy.
/// Receives SSH output from proxy, forwards to client.
///
/// Security: Session ownership is verified by the `ws_session_guard` middleware
/// before this handler is called. Only the session owner or staff/superuser
/// users can reach this handler.
pub async fn terminal_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    user: AuthUser,
) -> impl IntoResponse {
    info!(
        user = %user.username,
        session_id = %session_id,
        "Terminal WebSocket connection requested"
    );

    ws.on_upgrade(move |socket| handle_terminal_socket(socket, state, session_id, user))
}

/// Handle terminal WebSocket connection for SSH sessions.
async fn handle_terminal_socket(
    socket: WebSocket,
    state: AppState,
    session_id: String,
    user: AuthUser,
) {
    let (mut sender, mut receiver) = socket.split();

    info!(
        user = %user.username,
        session_id = %session_id,
        "Terminal WebSocket connected"
    );

    // Session ownership has been verified in terminal_ws() before the upgrade.

    // Check if we have the SSH proxy client
    let proxy_client = match &state.ssh_proxy {
        Some(client) => client.clone(),
        None => {
            error!(session_id = %session_id, "SSH proxy client not available");
            let _ = sender
                .send(Message::Text(
                    r#"{"error":"SSH proxy not available"}"#.to_string().into(),
                ))
                .await;
            return;
        }
    };

    // Subscribe to SSH data for this specific session
    let mut data_rx = proxy_client.subscribe_session(&session_id).await;

    // Create ping interval
    let mut ping_interval = interval(Duration::from_secs(PING_INTERVAL_SECS));
    let mut should_close = false;

    loop {
        tokio::select! {
            // Handle incoming messages from client (terminal input)
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        // Check if this is a control message (JSON with "type" field)
                        if text.starts_with('{') {
                            if let Ok(cmd) = serde_json::from_str::<TerminalCommand>(&text) {
                                match cmd {
                                    TerminalCommand::Resize { cols, rows } => {
                                        debug!(
                                            session_id = %session_id,
                                            cols = cols,
                                            rows = rows,
                                            "Terminal resize requested"
                                        );
                                        if let Err(e) = proxy_client.resize(&session_id, cols, rows) {
                                            warn!(session_id = %session_id, error = %e, "Failed to resize terminal");
                                        }
                                    }
                                    TerminalCommand::Data { data } => {
                                        // Explicit data command
                                        if let Err(e) = proxy_client.send_data(&session_id, data.as_bytes()) {
                                            error!(session_id = %session_id, error = %e, "Failed to send to SSH proxy");
                                            should_close = true;
                                        }
                                    }
                                }
                            } else {
                                // Not a valid command JSON, treat as terminal input
                                debug!(
                                    session_id = %session_id,
                                    len = text.len(),
                                    "Received terminal input"
                                );
                                if let Err(e) = proxy_client.send_data(&session_id, text.as_bytes()) {
                                    error!(session_id = %session_id, error = %e, "Failed to send to SSH proxy");
                                    should_close = true;
                                }
                            }
                        } else {
                            // Plain text input from terminal
                            debug!(
                                session_id = %session_id,
                                len = text.len(),
                                "Received terminal input"
                            );
                            if let Err(e) = proxy_client.send_data(&session_id, text.as_bytes()) {
                                error!(session_id = %session_id, error = %e, "Failed to send to SSH proxy");
                                should_close = true;
                            }
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        // Binary input from terminal
                        debug!(
                            session_id = %session_id,
                            len = data.len(),
                            "Received binary terminal input"
                        );
                        if let Err(e) = proxy_client.send_data(&session_id, &data) {
                            error!(session_id = %session_id, error = %e, "Failed to send to SSH proxy");
                            should_close = true;
                        }
                    }
                    Some(Ok(Message::Ping(_))) => {
                        debug!(session_id = %session_id, "Received WS ping");
                    }
                    Some(Ok(Message::Pong(_))) => {
                        debug!(session_id = %session_id, "Received WS pong");
                    }
                    Some(Ok(Message::Close(_))) => {
                        info!(session_id = %session_id, "Client requested close");
                        // Close the SSH session
                        if let Err(e) = proxy_client.close_session(&session_id) {
                            warn!(session_id = %session_id, error = %e, "Failed to close SSH session");
                        }
                        should_close = true;
                    }
                    Some(Err(e)) => {
                        error!(session_id = %session_id, error = %e, "WebSocket error");
                        should_close = true;
                    }
                    None => {
                        info!(session_id = %session_id, "WebSocket stream ended");
                        should_close = true;
                    }
                }
            }

            // SSH output from proxy -> send to client
            result = data_rx.recv() => {
                match result {
                    Some(data) => {
                        // Send binary data to terminal
                        if sender.send(Message::Binary(data.into())).await.is_err() {
                            warn!(session_id = %session_id, "Failed to send SSH output to WebSocket");
                            should_close = true;
                        }
                    }
                    None => {
                        // Channel closed - IPC connection lost or session ended
                        warn!(session_id = %session_id, "SSH data channel closed");
                        should_close = true;
                    }
                }
            }

            // Send periodic ping
            _ = ping_interval.tick() => {
                if sender.send(Message::Ping(vec![].into())).await.is_err() {
                    warn!(session_id = %session_id, "Failed to send ping");
                    should_close = true;
                }
            }
        }

        if should_close {
            break;
        }
    }

    // Unsubscribe from session data
    proxy_client.unsubscribe_session(&session_id).await;

    info!(
        user = %user.username,
        session_id = %session_id,
        "Terminal WebSocket disconnected"
    );
}

/// Terminal resize message from client.
#[derive(serde::Deserialize)]
pub struct TerminalResize {
    pub cols: u16,
    pub rows: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== WsChannel Tests ====================

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

    #[test]
    fn test_ws_channel_active_sessions() {
        let channel = WsChannel::ActiveSessions;
        assert_eq!(channel.as_str(), "dashboard:active-sessions");
    }

    #[test]
    fn test_ws_channel_active_sessions_list() {
        let channel = WsChannel::ActiveSessionsList;
        assert_eq!(channel.as_str(), "sessions:active-list");
    }

    #[test]
    fn test_ws_channel_recent_activity() {
        let channel = WsChannel::RecentActivity;
        assert_eq!(channel.as_str(), "dashboard:recent-activity");
    }

    #[test]
    fn test_ws_channel_notifications() {
        let channel = WsChannel::Notifications;
        assert_eq!(channel.as_str(), "notifications");
    }

    #[test]
    fn test_ws_channel_user_auth_sessions() {
        let channel = WsChannel::UserAuthSessions("user-uuid-123".to_string());
        assert_eq!(channel.as_str(), "user:user-uuid-123:auth-sessions");
    }

    #[test]
    fn test_ws_channel_user_api_keys() {
        let channel = WsChannel::UserApiKeys("user-uuid-456".to_string());
        assert_eq!(channel.as_str(), "user:user-uuid-456:api-keys");
    }

    // ==================== PING_INTERVAL Tests ====================

    #[test]
    fn test_ping_interval_value() {
        assert_eq!(PING_INTERVAL_SECS, 30);
    }

    #[test]
    fn test_ping_interval_as_duration() {
        let duration = Duration::from_secs(PING_INTERVAL_SECS);
        assert_eq!(duration.as_secs(), 30);
        assert_eq!(duration.as_millis(), 30_000);
    }

    #[test]
    fn test_ping_interval_reasonable() {
        // Should be between 10 seconds and 2 minutes
        assert!(PING_INTERVAL_SECS >= 10);
        assert!(PING_INTERVAL_SECS <= 120);
    }

    // ==================== WsChannel Additional Tests ====================

    #[test]
    fn test_ws_channel_clone() {
        let channel = WsChannel::SessionLive("session-123".to_string());
        let cloned = channel.clone();

        assert_eq!(channel.as_str(), cloned.as_str());
    }

    #[test]
    fn test_ws_channel_debug() {
        let channel = WsChannel::DashboardStats;
        let debug_str = format!("{:?}", channel);

        assert!(debug_str.contains("DashboardStats"));
    }

    #[test]
    fn test_ws_channel_hash_eq() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(WsChannel::DashboardStats);
        set.insert(WsChannel::ActiveSessions);
        set.insert(WsChannel::DashboardStats); // duplicate

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_ws_channel_session_live_different_ids() {
        let channel1 = WsChannel::SessionLive("abc".to_string());
        let channel2 = WsChannel::SessionLive("xyz".to_string());

        assert_ne!(channel1.as_str(), channel2.as_str());
    }

    #[test]
    fn test_ws_channel_user_channels_different_users() {
        let auth1 = WsChannel::UserAuthSessions("user-1".to_string());
        let auth2 = WsChannel::UserAuthSessions("user-2".to_string());
        let api1 = WsChannel::UserApiKeys("user-1".to_string());

        assert_ne!(auth1.as_str(), auth2.as_str());
        assert_ne!(auth1.as_str(), api1.as_str());
    }

    #[test]
    fn test_ws_channel_from_str() {
        assert_eq!(
            WsChannel::parse("dashboard:stats"),
            Some(WsChannel::DashboardStats)
        );
        assert_eq!(
            WsChannel::parse("dashboard:active-sessions"),
            Some(WsChannel::ActiveSessions)
        );
        assert_eq!(
            WsChannel::parse("dashboard:recent-activity"),
            Some(WsChannel::RecentActivity)
        );
        assert_eq!(
            WsChannel::parse("notifications"),
            Some(WsChannel::Notifications)
        );
        assert_eq!(WsChannel::parse("invalid"), None);
    }

    #[test]
    fn test_ws_channel_roundtrip() {
        let channels = vec![
            WsChannel::DashboardStats,
            WsChannel::ActiveSessions,
            WsChannel::RecentActivity,
            WsChannel::Notifications,
            WsChannel::SessionLive("test-id".to_string()),
            WsChannel::UserAuthSessions("user-uuid".to_string()),
            WsChannel::UserApiKeys("user-uuid".to_string()),
        ];

        for channel in channels {
            let str_val = channel.as_str();
            let parsed = WsChannel::parse(&str_val);
            assert!(parsed.is_some(), "Failed to parse: {}", str_val);
        }
    }

    // ==================== Token Hash Tests ====================

    #[test]
    fn test_sha3_256_hash_length() {
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();
        hasher.update(b"test-token");
        let hash = format!("{:x}", hasher.finalize());

        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_sha3_256_hash_deterministic() {
        use sha3::{Digest, Sha3_256};

        let compute_hash = |input: &[u8]| {
            let mut hasher = Sha3_256::new();
            hasher.update(input);
            format!("{:x}", hasher.finalize())
        };

        let hash1 = compute_hash(b"same-token");
        let hash2 = compute_hash(b"same-token");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha3_256_hash_different_inputs() {
        use sha3::{Digest, Sha3_256};

        let compute_hash = |input: &[u8]| {
            let mut hasher = Sha3_256::new();
            hasher.update(input);
            format!("{:x}", hasher.finalize())
        };

        let hash1 = compute_hash(b"token-a");
        let hash2 = compute_hash(b"token-b");

        assert_ne!(hash1, hash2);
    }

    // ==================== Duration Tests ====================

    #[test]
    fn test_duration_from_secs() {
        let duration = Duration::from_secs(30);
        assert_eq!(duration.as_secs(), 30);
    }

    #[tokio::test]
    async fn test_interval_tick_immediate() {
        // Verify interval creation doesn't panic
        let mut ticker = interval(Duration::from_secs(1));
        // First tick is immediate
        ticker.tick().await;
    }
}
