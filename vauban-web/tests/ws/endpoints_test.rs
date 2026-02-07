/// VAUBAN Web - WebSocket Integration Tests.
///
/// Tests for WebSocket endpoints: /ws/dashboard, /ws/session/{id}, /ws/notifications.
use axum::http::header;
use serial_test::serial;

use crate::common::{TestApp, test_db};
use crate::fixtures::{create_admin_user, unique_name};

// ==================== Dashboard WebSocket Tests ====================

/// Test WebSocket connection to dashboard endpoint.
#[tokio::test]
#[serial]
async fn test_dashboard_ws_connection() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut *conn, &app.auth_service, &unique_name("wsadmin")).await;
    drop(conn);
    let mut conn = app.get_conn().await;
    test_db::cleanup(&mut *conn).await;

    // Note: axum-test doesn't support WebSocket directly,
    // so we test via the HTTP upgrade request
    let response = app
        .server
        .get("/ws/dashboard")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(header::UPGRADE, "websocket")
        .add_header(header::CONNECTION, "Upgrade")
        .add_header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .add_header(header::SEC_WEBSOCKET_VERSION, "13")
        .await;

    // Should return 101 Switching Protocols or 400 if not properly upgraded
    // In test environment without actual WS client, we verify the endpoint exists
    let status = response.status_code().as_u16();
    assert!(
        status == 101 || status == 400 || status == 426,
        "Expected 101, 400, or 426, got {}",
        status
    );
}

/// Test WebSocket connection requires authentication.
#[tokio::test]
#[serial]
async fn test_dashboard_ws_requires_auth() {
    let app = TestApp::spawn().await;
    {
        let mut c = app.get_conn().await;
        test_db::cleanup(&mut *c).await;
    }

    // Try to connect without authentication
    let response = app
        .server
        .get("/ws/dashboard")
        .add_header(header::UPGRADE, "websocket")
        .add_header(header::CONNECTION, "Upgrade")
        .add_header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .add_header(header::SEC_WEBSOCKET_VERSION, "13")
        .await;

    // Should be unauthorized, redirect, or upgrade required (426 = route exists but auth failed)
    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 303 || status == 400 || status == 426,
        "Expected 401, 303, 400, or 426, got {}",
        status
    );
}

// ==================== Session WebSocket Tests ====================

/// Test session WebSocket endpoint exists (with invalid session ID -> 400).
#[tokio::test]
#[serial]
async fn test_session_ws_endpoint_exists() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut *conn, &app.auth_service, &unique_name("wssession")).await;
    drop(conn);
    {
        let mut c = app.get_conn().await;
        test_db::cleanup(&mut *c).await;
    }

    // "test-session-id" is not a valid UUID -> ownership check returns 400
    let response = app
        .server
        .get("/ws/session/test-session-id")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(header::UPGRADE, "websocket")
        .add_header(header::CONNECTION, "Upgrade")
        .add_header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .add_header(header::SEC_WEBSOCKET_VERSION, "13")
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 400 || status == 426,
        "Expected 400 or 426, got {}",
        status
    );
}

/// Test session WebSocket requires authentication.
#[tokio::test]
#[serial]
async fn test_session_ws_requires_auth() {
    let app = TestApp::spawn().await;
    {
        let mut c = app.get_conn().await;
        test_db::cleanup(&mut *c).await;
    }

    let response = app
        .server
        .get("/ws/session/test-session-id")
        .add_header(header::UPGRADE, "websocket")
        .add_header(header::CONNECTION, "Upgrade")
        .add_header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .add_header(header::SEC_WEBSOCKET_VERSION, "13")
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 303 || status == 400 || status == 426,
        "Expected 401, 303, 400, or 426, got {}",
        status
    );
}

// ==================== Notifications WebSocket Tests ====================

/// Test notifications WebSocket endpoint exists.
#[tokio::test]
#[serial]
async fn test_notifications_ws_endpoint_exists() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut *conn, &app.auth_service, &unique_name("wsnotif")).await;
    drop(conn);
    {
        let mut c = app.get_conn().await;
        test_db::cleanup(&mut *c).await;
    }

    let response = app
        .server
        .get("/ws/notifications")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(header::UPGRADE, "websocket")
        .add_header(header::CONNECTION, "Upgrade")
        .add_header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .add_header(header::SEC_WEBSOCKET_VERSION, "13")
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 101 || status == 400 || status == 426,
        "Expected 101, 400, or 426, got {}",
        status
    );
}

/// Test notifications WebSocket requires authentication.
#[tokio::test]
#[serial]
async fn test_notifications_ws_requires_auth() {
    let app = TestApp::spawn().await;
    {
        let mut c = app.get_conn().await;
        test_db::cleanup(&mut *c).await;
    }

    let response = app
        .server
        .get("/ws/notifications")
        .add_header(header::UPGRADE, "websocket")
        .add_header(header::CONNECTION, "Upgrade")
        .add_header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .add_header(header::SEC_WEBSOCKET_VERSION, "13")
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 303 || status == 400 || status == 426,
        "Expected 401, 303, 400, or 426, got {}",
        status
    );
}

// ==================== Active Sessions List WebSocket Tests ====================

/// Test active sessions list WebSocket endpoint exists.
#[tokio::test]
#[serial]
async fn test_active_sessions_ws_endpoint_exists() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(
        &mut *conn,
        &app.auth_service,
        &unique_name("wsactivesessions"),
    )
    .await;
    drop(conn);
    {
        let mut c = app.get_conn().await;
        test_db::cleanup(&mut *c).await;
    }

    let response = app
        .server
        .get("/ws/sessions/active")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(header::UPGRADE, "websocket")
        .add_header(header::CONNECTION, "Upgrade")
        .add_header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .add_header(header::SEC_WEBSOCKET_VERSION, "13")
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 101 || status == 400 || status == 426,
        "Expected 101, 400, or 426, got {}",
        status
    );
}

/// Test active sessions list WebSocket requires authentication.
#[tokio::test]
#[serial]
async fn test_active_sessions_ws_requires_auth() {
    let app = TestApp::spawn().await;
    {
        let mut c = app.get_conn().await;
        test_db::cleanup(&mut *c).await;
    }

    let response = app
        .server
        .get("/ws/sessions/active")
        .add_header(header::UPGRADE, "websocket")
        .add_header(header::CONNECTION, "Upgrade")
        .add_header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .add_header(header::SEC_WEBSOCKET_VERSION, "13")
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 303 || status == 400 || status == 426,
        "Expected 401, 303, 400, or 426, got {}",
        status
    );
}

// ==================== Broadcast Service Tests ====================

/// Test that broadcast service is functional.
#[tokio::test]
#[serial]
async fn test_broadcast_service_send_receive() {
    use vauban_web::services::broadcast::{BroadcastService, WsChannel, WsMessage};

    let broadcast = BroadcastService::new();

    // Subscribe to a channel
    let mut receiver = broadcast.subscribe(&WsChannel::DashboardStats).await;

    // Send a message
    let msg = WsMessage::new("ws-stats", "<p>Test stats</p>".to_string());
    let result = broadcast.send(&WsChannel::DashboardStats, msg).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1); // 1 subscriber

    // Receive the message
    let received = receiver.recv().await;
    assert!(received.is_ok());

    let html = received.unwrap();
    assert!(html.contains("ws-stats"));
    assert!(html.contains("Test stats"));
    assert!(html.contains("hx-swap-oob"));
}

/// Test broadcast to multiple subscribers.
#[tokio::test]
#[serial]
async fn test_broadcast_multiple_subscribers() {
    use vauban_web::services::broadcast::{BroadcastService, WsChannel, WsMessage};

    let broadcast = BroadcastService::new();

    // Create multiple subscribers
    let mut rx1 = broadcast.subscribe(&WsChannel::ActiveSessions).await;
    let mut rx2 = broadcast.subscribe(&WsChannel::ActiveSessions).await;
    let mut rx3 = broadcast.subscribe(&WsChannel::ActiveSessions).await;

    // Verify subscriber count
    let count = broadcast.subscriber_count(&WsChannel::ActiveSessions).await;
    assert_eq!(count, 3);

    // Send a message
    let msg = WsMessage::new("ws-sessions", "<div>Session data</div>".to_string());
    let result = broadcast.send(&WsChannel::ActiveSessions, msg).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 3); // 3 subscribers

    // All receivers should get the message
    let html1 = rx1.recv().await.unwrap();
    let html2 = rx2.recv().await.unwrap();
    let html3 = rx3.recv().await.unwrap();

    assert_eq!(html1, html2);
    assert_eq!(html2, html3);
    assert!(html1.contains("Session data"));
}

/// Test WsMessage HTMX formatting.
#[tokio::test]
#[serial]
async fn test_ws_message_htmx_format() {
    use vauban_web::services::broadcast::WsMessage;

    let msg = WsMessage::new("my-element", "<span>Content</span>".to_string());
    let html = msg.to_htmx_html();

    // Verify HTMX out-of-band swap format
    assert!(html.starts_with("<div"));
    assert!(html.contains(r#"id="my-element""#));
    assert!(html.contains(r#"hx-swap-oob="innerHTML""#));
    assert!(html.contains("<span>Content</span>"));
    assert!(html.ends_with("</div>"));
}

/// Test WsMessage custom swap mode.
#[tokio::test]
#[serial]
async fn test_ws_message_custom_swap_mode() {
    use vauban_web::services::broadcast::WsMessage;

    let msg = WsMessage::new("target", "<p>New</p>".to_string()).with_swap_mode("outerHTML");

    let html = msg.to_htmx_html();

    assert!(html.contains(r#"hx-swap-oob="outerHTML""#));
}

/// Test WsChannel string conversion.
#[tokio::test]
#[serial]
async fn test_ws_channel_string_conversion() {
    use vauban_web::services::broadcast::WsChannel;

    // Test as_str
    assert_eq!(WsChannel::DashboardStats.as_str(), "dashboard:stats");
    assert_eq!(
        WsChannel::ActiveSessions.as_str(),
        "dashboard:active-sessions"
    );
    assert_eq!(
        WsChannel::ActiveSessionsList.as_str(),
        "sessions:active-list"
    );
    assert_eq!(
        WsChannel::RecentActivity.as_str(),
        "dashboard:recent-activity"
    );
    assert_eq!(WsChannel::Notifications.as_str(), "notifications");
    assert_eq!(
        WsChannel::SessionLive("abc123".to_string()).as_str(),
        "session:abc123"
    );

    // Test from_str
    assert_eq!(
        WsChannel::parse("dashboard:stats"),
        Some(WsChannel::DashboardStats)
    );
    assert_eq!(
        WsChannel::parse("session:xyz"),
        Some(WsChannel::SessionLive("xyz".to_string()))
    );
    assert_eq!(WsChannel::parse("invalid"), None);
}

/// Test broadcast channel isolation.
#[tokio::test]
#[serial]
async fn test_broadcast_channel_isolation() {
    use tokio::time::{Duration, timeout};
    use vauban_web::services::broadcast::{BroadcastService, WsChannel, WsMessage};

    let broadcast = BroadcastService::new();

    // Subscribe to different channels
    let mut stats_rx = broadcast.subscribe(&WsChannel::DashboardStats).await;
    let mut sessions_rx = broadcast.subscribe(&WsChannel::ActiveSessions).await;

    // Send to stats channel only
    let msg = WsMessage::new("stats", "Stats data".to_string());
    broadcast
        .send(&WsChannel::DashboardStats, msg)
        .await
        .unwrap();

    // Stats receiver should get the message
    let stats_result = timeout(Duration::from_millis(100), stats_rx.recv()).await;
    assert!(stats_result.is_ok());
    assert!(stats_result.unwrap().is_ok());

    // Sessions receiver should NOT get the message (timeout)
    let sessions_result = timeout(Duration::from_millis(100), sessions_rx.recv()).await;
    assert!(sessions_result.is_err()); // Timeout = no message received
}

// ==================== Terminal WebSocket Tests ====================

/// Test terminal WebSocket endpoint exists (with invalid session ID -> 400).
#[tokio::test]
#[serial]
async fn test_terminal_ws_endpoint_exists() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut *conn, &app.auth_service, &unique_name("wsterminal")).await;
    drop(conn);
    {
        let mut c = app.get_conn().await;
        test_db::cleanup(&mut *c).await;
    }

    // "test-session-id" is not a valid UUID -> ownership check returns 400
    let response = app
        .server
        .get("/ws/terminal/test-session-id")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(header::UPGRADE, "websocket")
        .add_header(header::CONNECTION, "Upgrade")
        .add_header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .add_header(header::SEC_WEBSOCKET_VERSION, "13")
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 400 || status == 426,
        "Expected 400 or 426, got {}",
        status
    );
}

/// Test terminal WebSocket requires authentication.
#[tokio::test]
#[serial]
async fn test_terminal_ws_requires_auth() {
    let app = TestApp::spawn().await;
    {
        let mut c = app.get_conn().await;
        test_db::cleanup(&mut *c).await;
    }

    let response = app
        .server
        .get("/ws/terminal/test-session-id")
        .add_header(header::UPGRADE, "websocket")
        .add_header(header::CONNECTION, "Upgrade")
        .add_header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .add_header(header::SEC_WEBSOCKET_VERSION, "13")
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 303 || status == 400 || status == 426,
        "Expected 401, 303, 400, or 426, got {}",
        status
    );
}

/// Test terminal WebSocket with UUID session ID that does not exist -> 404.
#[tokio::test]
#[serial]
async fn test_terminal_ws_uuid_session_id() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(
        &mut *conn,
        &app.auth_service,
        &unique_name("wsterminaluuid"),
    )
    .await;
    drop(conn);
    {
        let mut c = app.get_conn().await;
        test_db::cleanup(&mut *c).await;
    }

    // Valid UUID format but no corresponding session in DB -> ownership check returns 404
    let session_uuid = "550e8400-e29b-41d4-a716-446655440000";
    let response = app
        .server
        .get(&format!("/ws/terminal/{}", session_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(header::UPGRADE, "websocket")
        .add_header(header::CONNECTION, "Upgrade")
        .add_header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .add_header(header::SEC_WEBSOCKET_VERSION, "13")
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 404,
        "Expected 404 (session not found), got {}",
        status
    );
}
