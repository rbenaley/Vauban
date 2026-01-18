/// VAUBAN Web - Broadcast Service Tests.
///
/// Tests for the WebSocket broadcast service.
use serial_test::serial;
use std::time::Duration;
use uuid::Uuid;

use crate::common::TestApp;

// =============================================================================
// Broadcast Service Tests
// =============================================================================

/// Test that broadcast service can send messages.
#[tokio::test]
#[serial]
async fn test_broadcast_service_sends_messages() {
    use vauban_web::services::broadcast::WsChannel;

    let app = TestApp::spawn().await;

    // Subscribe to a channel
    let channel = WsChannel::DashboardStats;
    let mut receiver = app.broadcast.subscribe(&channel).await;

    // Send a test message
    let test_html = "<div>Test stats update</div>".to_string();
    let msg = vauban_web::services::broadcast::WsMessage::new("ws-stats", test_html.clone());

    let result = app.broadcast.send(&channel, msg).await;
    assert!(result.is_ok(), "Broadcast send should succeed");

    // Receive the message with timeout
    let received = tokio::time::timeout(Duration::from_secs(1), receiver.recv()).await;

    assert!(received.is_ok(), "Should receive message within timeout");
    let message = received.unwrap();
    assert!(message.is_ok(), "Message should be received successfully");
    assert!(message.unwrap().contains("Test stats update"));
}

/// Test broadcast to user-specific channel.
#[tokio::test]
#[serial]
async fn test_broadcast_to_user_channel() {
    use vauban_web::services::broadcast::WsChannel;

    let app = TestApp::spawn().await;
    let user_uuid = Uuid::new_v4().to_string();

    // Subscribe to user's channel
    let channel = WsChannel::UserAuthSessions(user_uuid.clone());
    let mut receiver = app.broadcast.subscribe(&channel).await;

    // Send a message to this user's channel
    let test_html = "<div>User sessions updated</div>".to_string();
    let msg = vauban_web::services::broadcast::WsMessage::new("ws-sessions", test_html.clone());

    let result = app.broadcast.send(&channel, msg).await;
    assert!(result.is_ok(), "User broadcast send should succeed");

    // Receive the message
    let received = tokio::time::timeout(Duration::from_secs(1), receiver.recv()).await;

    assert!(
        received.is_ok(),
        "Should receive user message within timeout"
    );
}

/// Test that messages are not received on different channels.
#[tokio::test]
#[serial]
async fn test_broadcast_channel_isolation() {
    use vauban_web::services::broadcast::WsChannel;

    let app = TestApp::spawn().await;

    // Subscribe to stats channel
    let stats_channel = WsChannel::DashboardStats;
    let mut stats_receiver = app.broadcast.subscribe(&stats_channel).await;

    // Send to sessions channel (different channel)
    let sessions_channel = WsChannel::ActiveSessions;
    let msg = vauban_web::services::broadcast::WsMessage::new("ws-sessions", "test".to_string());
    let _ = app.broadcast.send(&sessions_channel, msg).await;

    // Stats receiver should NOT receive the sessions message
    let received = tokio::time::timeout(Duration::from_millis(100), stats_receiver.recv()).await;

    // Should timeout (no message on stats channel)
    assert!(
        received.is_err(),
        "Stats channel should not receive sessions message"
    );
}

/// Test multiple subscribers receive the same message.
#[tokio::test]
#[serial]
async fn test_broadcast_multiple_subscribers() {
    use vauban_web::services::broadcast::WsChannel;

    let app = TestApp::spawn().await;

    let channel = WsChannel::RecentActivity;

    // Create multiple subscribers
    let mut receiver1 = app.broadcast.subscribe(&channel).await;
    let mut receiver2 = app.broadcast.subscribe(&channel).await;
    let mut receiver3 = app.broadcast.subscribe(&channel).await;

    // Send one message
    let msg = vauban_web::services::broadcast::WsMessage::new(
        "ws-activity",
        "activity update".to_string(),
    );
    let _ = app.broadcast.send(&channel, msg).await;

    // All receivers should get the message
    let recv1 = tokio::time::timeout(Duration::from_secs(1), receiver1.recv()).await;
    let recv2 = tokio::time::timeout(Duration::from_secs(1), receiver2.recv()).await;
    let recv3 = tokio::time::timeout(Duration::from_secs(1), receiver3.recv()).await;

    assert!(
        recv1.is_ok() && recv1.unwrap().is_ok(),
        "Receiver 1 should get message"
    );
    assert!(
        recv2.is_ok() && recv2.unwrap().is_ok(),
        "Receiver 2 should get message"
    );
    assert!(
        recv3.is_ok() && recv3.unwrap().is_ok(),
        "Receiver 3 should get message"
    );
}
