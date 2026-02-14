/// VAUBAN Web - User Connection Registry Tests.
///
/// Tests for WebSocket connection management.
use serial_test::serial;
use uuid::Uuid;

use crate::common::TestApp;

// =============================================================================
// User Connection Registry Tests
// =============================================================================

/// Test user connection registry registration.
#[tokio::test]
#[serial]
async fn test_user_connection_registry() {
    let app = TestApp::spawn().await;

    let user_uuid = Uuid::new_v4().to_string();
    let token_hash = "test_token_hash".to_string();

    // Register a connection
    let (conn_id, _receiver) = app.user_connections.register(&user_uuid, token_hash).await;

    // Check if user has connections
    let count = app.user_connections.connection_count(&user_uuid).await;
    assert_eq!(count, 1, "User should have 1 registered connection");

    // Unregister the connection
    app.user_connections.unregister(&user_uuid, conn_id).await;

    let count_after = app.user_connections.connection_count(&user_uuid).await;
    assert_eq!(
        count_after, 0,
        "User should have 0 connections after unregister"
    );
}

/// Test multiple connections per user.
#[tokio::test]
#[serial]
async fn test_user_multiple_connections() {
    let app = TestApp::spawn().await;

    let user_uuid = Uuid::new_v4().to_string();

    // Register multiple connections
    let (conn1, _rx1) = app
        .user_connections
        .register(&user_uuid, "hash1".to_string())
        .await;
    let (conn2, _rx2) = app
        .user_connections
        .register(&user_uuid, "hash2".to_string())
        .await;
    let (conn3, _rx3) = app
        .user_connections
        .register(&user_uuid, "hash3".to_string())
        .await;

    assert_eq!(app.user_connections.connection_count(&user_uuid).await, 3);

    // Unregister one
    app.user_connections.unregister(&user_uuid, conn1).await;

    // Should still have 2 connections
    assert_eq!(app.user_connections.connection_count(&user_uuid).await, 2);

    // Unregister all
    app.user_connections.unregister(&user_uuid, conn2).await;
    app.user_connections.unregister(&user_uuid, conn3).await;

    // Now should have no connections
    assert_eq!(app.user_connections.connection_count(&user_uuid).await, 0);
}

/// Test total connections across all users.
#[tokio::test]
#[serial]
async fn test_total_connections() {
    let app = TestApp::spawn().await;

    let user1 = Uuid::new_v4().to_string();
    let user2 = Uuid::new_v4().to_string();

    // Register connections for different users
    let (_conn1, _rx1) = app
        .user_connections
        .register(&user1, "hash1".to_string())
        .await;
    let (_conn2, _rx2) = app
        .user_connections
        .register(&user1, "hash2".to_string())
        .await;
    let (_conn3, _rx3) = app
        .user_connections
        .register(&user2, "hash3".to_string())
        .await;

    // Total should be 3
    let total = app.user_connections.total_connections().await;
    assert!(
        total >= 3,
        "Total connections should be at least 3, got {}",
        total
    );
}
