/// VAUBAN Web - User WebSocket connections registry.
///
/// Manages individual WebSocket connections with their context (token_hash)
/// to enable personalized messages (e.g., "Current session" indicator).
///
/// Also provides `WsConnectionCounter` (L-8): a per-user connection counter
/// applied as an Axum middleware to **all** WebSocket routes, ensuring every
/// current and future handler is automatically limited.
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, warn};
use uuid::Uuid;

// ============================================================================
// L-8: Per-user WebSocket connection counter (applied to all WS routes)
// ============================================================================

/// Error returned when a user exceeds the WebSocket connection limit.
#[derive(Debug)]
pub struct ConnectionLimitError {
    limit: usize,
}

impl std::fmt::Display for ConnectionLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WebSocket connection limit reached ({} per user)",
            self.limit
        )
    }
}

/// Per-user WebSocket connection counter (L-8).
///
/// Counts all active WebSocket connections per user across **all** handler
/// types (dashboard, notifications, terminal, session, active-sessions).
/// Applied as an Axum middleware layer on the `ws_routes` group so that
/// every current and future WebSocket handler is automatically limited.
///
/// The limit is read from `config.toml`: `[websocket] max_connections_per_user`.
#[derive(Clone)]
pub struct WsConnectionCounter {
    /// Map of user_uuid -> atomic connection count.
    counts: Arc<RwLock<HashMap<String, Arc<AtomicUsize>>>>,
    /// Configured maximum connections per user.
    max_per_user: usize,
}

impl WsConnectionCounter {
    /// Create a new counter with the given per-user limit.
    pub fn new(max_per_user: usize) -> Self {
        Self {
            counts: Arc::new(RwLock::new(HashMap::new())),
            max_per_user,
        }
    }

    /// Get the configured maximum connections per user.
    pub fn max_per_user(&self) -> usize {
        self.max_per_user
    }

    /// Try to acquire a connection slot for a user.
    ///
    /// Returns `Ok(WsConnectionGuard)` on success. The guard decrements the
    /// counter automatically when dropped (RAII), ensuring the count stays
    /// accurate even on panics or abrupt disconnections.
    ///
    /// Returns `Err(ConnectionLimitError)` if the limit is reached.
    pub async fn try_acquire(&self, user_uuid: &str) -> Result<WsConnectionGuard, ConnectionLimitError> {
        let mut counts = self.counts.write().await;
        let counter = counts
            .entry(user_uuid.to_string())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)));

        let current = counter.load(Ordering::Acquire);
        if current >= self.max_per_user {
            warn!(
                user_uuid = %user_uuid,
                current = current,
                limit = self.max_per_user,
                "WebSocket connection limit reached, rejecting new connection"
            );
            return Err(ConnectionLimitError {
                limit: self.max_per_user,
            });
        }

        counter.fetch_add(1, Ordering::Release);
        debug!(
            user_uuid = %user_uuid,
            count = current + 1,
            limit = self.max_per_user,
            "WebSocket connection slot acquired"
        );

        Ok(WsConnectionGuard {
            counter: Arc::clone(counter),
            user_uuid: user_uuid.to_string(),
        })
    }

    /// Get the current connection count for a user.
    pub async fn count(&self, user_uuid: &str) -> usize {
        let counts = self.counts.read().await;
        counts
            .get(user_uuid)
            .map(|c| c.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// Get total active connections across all users.
    pub async fn total(&self) -> usize {
        let counts = self.counts.read().await;
        counts.values().map(|c| c.load(Ordering::Acquire)).sum()
    }
}

/// RAII guard that decrements the per-user connection counter on drop.
///
/// Stored in the request extensions by the `ws_connection_limit` middleware.
/// When the WebSocket handler future completes (connection closed), the guard
/// is dropped and the counter is decremented automatically.
pub struct WsConnectionGuard {
    counter: Arc<AtomicUsize>,
    user_uuid: String,
}

impl std::fmt::Debug for WsConnectionGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsConnectionGuard")
            .field("user_uuid", &self.user_uuid)
            .field("count", &self.counter.load(Ordering::Acquire))
            .finish()
    }
}

impl Drop for WsConnectionGuard {
    fn drop(&mut self) {
        let prev = self.counter.fetch_sub(1, Ordering::Release);
        debug!(
            user_uuid = %self.user_uuid,
            count = prev.saturating_sub(1),
            "WebSocket connection slot released"
        );
    }
}

// ============================================================================
// User connection registry (personalized messaging)
// ============================================================================

/// A registered WebSocket connection with its context.
#[derive(Debug)]
pub struct UserConnection {
    /// Unique identifier for this connection.
    pub id: Uuid,
    /// The token hash of the session that established this connection.
    pub token_hash: String,
    /// Channel to send messages to this specific connection.
    pub sender: mpsc::Sender<String>,
}

/// Registry for user WebSocket connections.
/// Allows sending personalized messages to each connection.
///
/// Note: This registry handles **personalized messaging** (token_hash, send_personalized).
/// The per-user **connection limit** is enforced separately by `WsConnectionCounter`,
/// applied as a middleware layer on all WebSocket routes.
#[derive(Clone, Default)]
pub struct UserConnectionRegistry {
    /// Map of user_uuid -> list of connections.
    connections: Arc<RwLock<HashMap<String, Vec<UserConnection>>>>,
}

impl UserConnectionRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new connection for personalized messaging.
    ///
    /// Returns `(connection_id, receiver)`. This method does **not** enforce
    /// connection limits -- that is handled by `WsConnectionCounter` middleware.
    pub async fn register(
        &self,
        user_uuid: &str,
        token_hash: String,
    ) -> (Uuid, mpsc::Receiver<String>) {
        let (sender, receiver) = mpsc::channel(100);
        let connection_id = Uuid::new_v4();

        let connection = UserConnection {
            id: connection_id,
            token_hash,
            sender,
        };

        let mut connections = self.connections.write().await;
        connections
            .entry(user_uuid.to_string())
            .or_default()
            .push(connection);

        debug!(
            user_uuid = %user_uuid,
            connection_id = %connection_id,
            "Registered new WebSocket connection for personalized messaging"
        );

        (connection_id, receiver)
    }

    /// Unregister a connection when it closes.
    pub async fn unregister(&self, user_uuid: &str, connection_id: Uuid) {
        let mut connections = self.connections.write().await;
        if let Some(user_connections) = connections.get_mut(user_uuid) {
            user_connections.retain(|c| c.id != connection_id);
            if user_connections.is_empty() {
                connections.remove(user_uuid);
            }
            debug!(
                user_uuid = %user_uuid,
                connection_id = %connection_id,
                "Unregistered WebSocket connection"
            );
        }
    }

    /// Get all connections for a user with their token hashes.
    /// Returns a list of (connection_id, token_hash, sender) tuples.
    pub async fn get_user_connections(
        &self,
        user_uuid: &str,
    ) -> Vec<(Uuid, String, mpsc::Sender<String>)> {
        let connections = self.connections.read().await;
        connections
            .get(user_uuid)
            .map(|conns| {
                conns
                    .iter()
                    .map(|c| (c.id, c.token_hash.clone(), c.sender.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Send a message to all connections of a user.
    /// The message_fn receives the token_hash and returns the personalized HTML.
    pub async fn send_personalized<F>(&self, user_uuid: &str, message_fn: F)
    where
        F: Fn(&str) -> String,
    {
        let connections = self.get_user_connections(user_uuid).await;
        let count = connections.len();

        for (conn_id, token_hash, sender) in connections {
            let html = message_fn(&token_hash);
            if sender.send(html).await.is_err() {
                warn!(
                    user_uuid = %user_uuid,
                    connection_id = %conn_id,
                    "Failed to send personalized message, connection may be closed"
                );
            }
        }

        debug!(
            user_uuid = %user_uuid,
            connection_count = count,
            "Sent personalized messages to user connections"
        );
    }

    /// Get the number of active connections for a user.
    pub async fn connection_count(&self, user_uuid: &str) -> usize {
        let connections = self.connections.read().await;
        connections.get(user_uuid).map(|c| c.len()).unwrap_or(0)
    }

    /// Get the total number of active connections across all users.
    pub async fn total_connections(&self) -> usize {
        let connections = self.connections.read().await;
        connections.values().map(|c| c.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_connection() {
        let registry = UserConnectionRegistry::new();
        let (conn_id, _receiver) = registry.register("user-123", "hash-abc".to_string()).await;

        assert!(!conn_id.is_nil());
        assert_eq!(registry.connection_count("user-123").await, 1);
    }

    #[tokio::test]
    async fn test_register_multiple_connections() {
        let registry = UserConnectionRegistry::new();

        let (_id1, _rx1) = registry.register("user-123", "hash-a".to_string()).await;
        let (_id2, _rx2) = registry.register("user-123", "hash-b".to_string()).await;
        let (_id3, _rx3) = registry.register("user-456", "hash-c".to_string()).await;

        assert_eq!(registry.connection_count("user-123").await, 2);
        assert_eq!(registry.connection_count("user-456").await, 1);
        assert_eq!(registry.total_connections().await, 3);
    }

    #[tokio::test]
    async fn test_unregister_connection() {
        let registry = UserConnectionRegistry::new();

        let (conn_id, _rx) = registry.register("user-123", "hash-abc".to_string()).await;
        assert_eq!(registry.connection_count("user-123").await, 1);

        registry.unregister("user-123", conn_id).await;
        assert_eq!(registry.connection_count("user-123").await, 0);
    }

    #[tokio::test]
    async fn test_get_user_connections() {
        let registry = UserConnectionRegistry::new();

        let (_id1, _rx1) = registry.register("user-123", "hash-a".to_string()).await;
        let (_id2, _rx2) = registry.register("user-123", "hash-b".to_string()).await;

        let connections = registry.get_user_connections("user-123").await;
        assert_eq!(connections.len(), 2);

        let hashes: Vec<_> = connections.iter().map(|(_, h, _)| h.as_str()).collect();
        assert!(hashes.contains(&"hash-a"));
        assert!(hashes.contains(&"hash-b"));
    }

    #[tokio::test]
    async fn test_send_personalized() {
        let registry = UserConnectionRegistry::new();

        let (_id1, mut rx1) = registry.register("user-123", "hash-a".to_string()).await;
        let (_id2, mut rx2) = registry.register("user-123", "hash-b".to_string()).await;

        // Send personalized messages
        registry
            .send_personalized("user-123", |token_hash| {
                format!("Hello, your hash is: {}", token_hash)
            })
            .await;

        // Verify each receiver got personalized content
        let msg1 = unwrap_some!(rx1.recv().await);
        let msg2 = unwrap_some!(rx2.recv().await);

        assert!(msg1.contains("hash-a"));
        assert!(msg2.contains("hash-b"));
    }

    #[tokio::test]
    async fn test_empty_registry() {
        let registry = UserConnectionRegistry::new();

        assert_eq!(registry.connection_count("nonexistent").await, 0);
        assert_eq!(registry.total_connections().await, 0);

        let connections = registry.get_user_connections("nonexistent").await;
        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn test_registry_empty_on_creation() {
        let registry = UserConnectionRegistry::new();
        assert_eq!(registry.total_connections().await, 0);
    }

    #[tokio::test]
    async fn test_registry_clone() {
        let registry = UserConnectionRegistry::new();
        let (_id, _rx) = registry.register("user-1", "hash-1".to_string()).await;

        let cloned = registry.clone();
        // Both should see the same connections (shared state)
        assert_eq!(cloned.connection_count("user-1").await, 1);
    }

    #[tokio::test]
    async fn test_unregister_nonexistent_user() {
        let registry = UserConnectionRegistry::new();
        // Should not panic
        registry.unregister("nonexistent", Uuid::new_v4()).await;
        assert_eq!(registry.total_connections().await, 0);
    }

    #[tokio::test]
    async fn test_unregister_wrong_connection_id() {
        let registry = UserConnectionRegistry::new();
        let (_id, _rx) = registry.register("user-1", "hash-1".to_string()).await;

        // Try to unregister with wrong ID
        registry.unregister("user-1", Uuid::new_v4()).await;

        // Connection should still exist
        assert_eq!(registry.connection_count("user-1").await, 1);
    }

    #[tokio::test]
    async fn test_send_personalized_to_nonexistent_user() {
        let registry = UserConnectionRegistry::new();

        // Should not panic
        registry
            .send_personalized("nonexistent", |_| "test".to_string())
            .await;
    }

    #[tokio::test]
    async fn test_connection_ids_are_unique() {
        let registry = UserConnectionRegistry::new();

        let (id1, _rx1) = registry.register("user-1", "hash-1".to_string()).await;
        let (id2, _rx2) = registry.register("user-1", "hash-2".to_string()).await;
        let (id3, _rx3) = registry.register("user-2", "hash-3".to_string()).await;

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[tokio::test]
    async fn test_unregister_last_connection_removes_user() {
        let registry = UserConnectionRegistry::new();

        let (id, _rx) = registry.register("user-1", "hash-1".to_string()).await;
        assert_eq!(registry.connection_count("user-1").await, 1);

        registry.unregister("user-1", id).await;
        assert_eq!(registry.connection_count("user-1").await, 0);

        // User should be completely removed from the map
        let connections = registry.connections.read().await;
        assert!(!connections.contains_key("user-1"));
    }

    // ==================== Additional Tests ====================

    #[tokio::test]
    async fn test_multiple_users_isolation() {
        let registry = UserConnectionRegistry::new();

        let (_id1, _rx1) = registry.register("user-a", "hash-a".to_string()).await;
        let (_id2, _rx2) = registry.register("user-b", "hash-b".to_string()).await;

        // Each user should have their own connections
        let conns_a = registry.get_user_connections("user-a").await;
        let conns_b = registry.get_user_connections("user-b").await;

        assert_eq!(conns_a.len(), 1);
        assert_eq!(conns_b.len(), 1);
        assert_eq!(conns_a[0].1, "hash-a");
        assert_eq!(conns_b[0].1, "hash-b");
    }

    #[tokio::test]
    async fn test_send_personalized_different_messages() {
        let registry = UserConnectionRegistry::new();

        let (_id1, mut rx1) = registry.register("user-1", "token-AAA".to_string()).await;
        let (_id2, mut rx2) = registry.register("user-1", "token-BBB".to_string()).await;

        registry
            .send_personalized("user-1", |hash| {
                if hash == "token-AAA" {
                    "Message for A".to_string()
                } else {
                    "Message for B".to_string()
                }
            })
            .await;

        let msg1 = unwrap_some!(rx1.recv().await);
        let msg2 = unwrap_some!(rx2.recv().await);

        assert_eq!(msg1, "Message for A");
        assert_eq!(msg2, "Message for B");
    }

    #[tokio::test]
    async fn test_receiver_channel_capacity() {
        let registry = UserConnectionRegistry::new();
        let (_id, mut rx) = registry.register("user-1", "hash".to_string()).await;

        // Send multiple messages
        for i in 0..10 {
            registry
                .send_personalized("user-1", |_| format!("msg-{}", i))
                .await;
        }

        // Should be able to receive all
        for i in 0..10 {
            let msg = unwrap_some!(rx.recv().await);
            assert_eq!(msg, format!("msg-{}", i));
        }
    }

    #[tokio::test]
    async fn test_partial_unregister() {
        let registry = UserConnectionRegistry::new();

        let (id1, _rx1) = registry.register("user-1", "hash-1".to_string()).await;
        let (_id2, _rx2) = registry.register("user-1", "hash-2".to_string()).await;
        let (_id3, _rx3) = registry.register("user-1", "hash-3".to_string()).await;

        assert_eq!(registry.connection_count("user-1").await, 3);

        // Unregister only one
        registry.unregister("user-1", id1).await;

        assert_eq!(registry.connection_count("user-1").await, 2);

        // Remaining connections should still have correct hashes
        let conns = registry.get_user_connections("user-1").await;
        let hashes: Vec<_> = conns.iter().map(|(_, h, _)| h.as_str()).collect();
        assert!(hashes.contains(&"hash-2"));
        assert!(hashes.contains(&"hash-3"));
        assert!(!hashes.contains(&"hash-1"));
    }

    #[tokio::test]
    async fn test_empty_token_hash() {
        let registry = UserConnectionRegistry::new();
        let (_id, mut rx) = registry.register("user-1", "".to_string()).await;

        registry
            .send_personalized("user-1", |hash| {
                format!("Hash is empty: {}", hash.is_empty())
            })
            .await;

        let msg = unwrap_some!(rx.recv().await);
        assert_eq!(msg, "Hash is empty: true");
    }

    #[tokio::test]
    async fn test_unicode_user_uuid() {
        let registry = UserConnectionRegistry::new();
        let user_uuid = "用户-123";

        let (_id, _rx) = registry.register(user_uuid, "hash".to_string()).await;

        assert_eq!(registry.connection_count(user_uuid).await, 1);
    }

    #[tokio::test]
    async fn test_long_token_hash() {
        let registry = UserConnectionRegistry::new();
        let long_hash = "a".repeat(1000);

        let (_id, _rx) = registry.register("user-1", long_hash.clone()).await;

        let conns = registry.get_user_connections("user-1").await;
        assert_eq!(conns[0].1.len(), 1000);
    }

    #[tokio::test]
    async fn test_concurrent_registrations() {
        let registry = UserConnectionRegistry::new();
        let registry_clone = registry.clone();

        let handle1 = tokio::spawn(async move {
            for i in 0..5 {
                let _ = registry_clone
                    .register("user-a", format!("hash-{}", i))
                    .await;
            }
        });

        let registry_clone2 = registry.clone();
        let handle2 = tokio::spawn(async move {
            for i in 0..5 {
                let _ = registry_clone2
                    .register("user-b", format!("hash-{}", i))
                    .await;
            }
        });

        unwrap_ok!(handle1.await);
        unwrap_ok!(handle2.await);

        assert_eq!(registry.connection_count("user-a").await, 5);
        assert_eq!(registry.connection_count("user-b").await, 5);
        assert_eq!(registry.total_connections().await, 10);
    }

    // ==================== UserConnection Tests ====================

    #[test]
    fn test_user_connection_debug() {
        let (tx, _rx) = mpsc::channel(1);
        let conn = UserConnection {
            id: Uuid::nil(),
            token_hash: "test-hash".to_string(),
            sender: tx,
        };

        let debug_str = format!("{:?}", conn);
        assert!(debug_str.contains("UserConnection"));
        assert!(debug_str.contains("token_hash"));
    }

    #[test]
    fn test_user_connection_fields() {
        let (tx, _rx) = mpsc::channel(1);
        let id = Uuid::new_v4();
        let hash = "my-hash".to_string();

        let conn = UserConnection {
            id,
            token_hash: hash.clone(),
            sender: tx,
        };

        assert_eq!(conn.id, id);
        assert_eq!(conn.token_hash, hash);
    }

    // ==================== Send Personalized Edge Cases ====================

    #[tokio::test]
    async fn test_send_personalized_receiver_dropped() {
        let registry = UserConnectionRegistry::new();

        let (_id, rx) = registry.register("user-1", "hash-1".to_string()).await;

        // Drop the receiver before sending
        drop(rx);

        // Should not panic, just warn
        registry
            .send_personalized("user-1", |_| "test message".to_string())
            .await;
    }

    #[tokio::test]
    async fn test_send_personalized_some_receivers_dropped() {
        let registry = UserConnectionRegistry::new();

        let (_id1, rx1) = registry.register("user-1", "hash-1".to_string()).await;
        let (_id2, mut rx2) = registry.register("user-1", "hash-2".to_string()).await;

        // Drop only one receiver
        drop(rx1);

        registry
            .send_personalized("user-1", |hash| format!("msg for {}", hash))
            .await;

        // rx2 should still receive
        let msg = unwrap_some!(rx2.recv().await);
        assert_eq!(msg, "msg for hash-2");
    }

    // ==================== Total Connections Tests ====================

    #[tokio::test]
    async fn test_total_connections_multiple_users() {
        let registry = UserConnectionRegistry::new();

        let (_id1, _rx1) = registry.register("user-a", "h1".to_string()).await;
        let (_id2, _rx2) = registry.register("user-a", "h2".to_string()).await;
        let (_id3, _rx3) = registry.register("user-b", "h3".to_string()).await;
        let (_id4, _rx4) = registry.register("user-c", "h4".to_string()).await;

        assert_eq!(registry.total_connections().await, 4);
    }

    #[tokio::test]
    async fn test_total_connections_after_unregister() {
        let registry = UserConnectionRegistry::new();

        let (id1, _rx1) = registry.register("user-a", "h1".to_string()).await;
        let (_id2, _rx2) = registry.register("user-b", "h2".to_string()).await;

        assert_eq!(registry.total_connections().await, 2);

        registry.unregister("user-a", id1).await;

        assert_eq!(registry.total_connections().await, 1);
    }

    // ==================== Connection Count Edge Cases ====================

    #[tokio::test]
    async fn test_connection_count_after_all_unregistered() {
        let registry = UserConnectionRegistry::new();

        let (id1, _rx1) = registry.register("user-1", "h1".to_string()).await;
        let (id2, _rx2) = registry.register("user-1", "h2".to_string()).await;

        registry.unregister("user-1", id1).await;
        registry.unregister("user-1", id2).await;

        assert_eq!(registry.connection_count("user-1").await, 0);
        assert_eq!(registry.total_connections().await, 0);
    }

    // ==================== Get User Connections Edge Cases ====================

    #[tokio::test]
    async fn test_get_user_connections_empty_user() {
        let registry = UserConnectionRegistry::new();

        let (_id, _rx) = registry.register("", "hash".to_string()).await;

        let conns = registry.get_user_connections("").await;
        assert_eq!(conns.len(), 1);
    }

    #[tokio::test]
    async fn test_get_user_connections_preserves_order() {
        let registry = UserConnectionRegistry::new();

        let (id1, _rx1) = registry.register("user-1", "first".to_string()).await;
        let (id2, _rx2) = registry.register("user-1", "second".to_string()).await;
        let (id3, _rx3) = registry.register("user-1", "third".to_string()).await;

        let conns = registry.get_user_connections("user-1").await;

        // Should be in registration order
        assert_eq!(conns[0].0, id1);
        assert_eq!(conns[1].0, id2);
        assert_eq!(conns[2].0, id3);
    }

    // ==================== Sender Tests ====================

    #[tokio::test]
    async fn test_connection_sender_works() {
        let registry = UserConnectionRegistry::new();

        let (_id, _rx) = registry.register("user-1", "hash".to_string()).await;

        let conns = registry.get_user_connections("user-1").await;
        let (_, _, sender) = &conns[0];

        // Should be able to send through the sender
        assert!(sender.send("test".to_string()).await.is_ok());
    }

    #[tokio::test]
    async fn test_connection_sender_closed() {
        let registry = UserConnectionRegistry::new();

        let (_id, rx) = registry.register("user-1", "hash".to_string()).await;

        let conns = registry.get_user_connections("user-1").await;
        let (_, _, sender) = &conns[0];

        // Drop receiver
        drop(rx);

        // Sender should fail
        assert!(sender.send("test".to_string()).await.is_err());
    }

    // ==================== UUID Tests ====================

    #[tokio::test]
    async fn test_connection_id_not_nil() {
        let registry = UserConnectionRegistry::new();

        let (id, _rx) = registry.register("user-1", "hash".to_string()).await;

        assert!(!id.is_nil());
    }

    #[tokio::test]
    async fn test_connection_id_version() {
        let registry = UserConnectionRegistry::new();

        let (id, _rx) = registry.register("user-1", "hash".to_string()).await;

        // Should be v4 (random) UUID
        assert_eq!(id.get_version_num(), 4);
    }

    // ==================== Stress Tests ====================

    #[tokio::test]
    async fn test_many_connections_same_user() {
        let registry = UserConnectionRegistry::new();

        let mut receivers = Vec::new();
        for i in 0..50 {
            let (_id, rx) = registry
                .register("user-1", format!("hash-{}", i))
                .await;
            receivers.push(rx);
        }

        assert_eq!(registry.connection_count("user-1").await, 50);
        assert_eq!(registry.total_connections().await, 50);
    }

    // ==================== L-8: WsConnectionCounter Tests ====================

    #[tokio::test]
    async fn test_l8_counter_basic_acquire_and_drop() {
        let counter = WsConnectionCounter::new(10);
        assert_eq!(counter.count("user-1").await, 0);

        let guard = counter.try_acquire("user-1").await.unwrap();
        assert_eq!(counter.count("user-1").await, 1);

        drop(guard);
        assert_eq!(counter.count("user-1").await, 0);
    }

    #[tokio::test]
    async fn test_l8_counter_limit_reached() {
        let counter = WsConnectionCounter::new(3);
        assert_eq!(counter.max_per_user(), 3);

        // Fill up to the limit
        let _g1 = counter.try_acquire("user-1").await.unwrap();
        let _g2 = counter.try_acquire("user-1").await.unwrap();
        let _g3 = counter.try_acquire("user-1").await.unwrap();

        // 4th should fail
        let result = counter.try_acquire("user-1").await;
        assert!(result.is_err(), "L-8: Should reject beyond limit");
        assert_eq!(counter.count("user-1").await, 3);
    }

    #[tokio::test]
    async fn test_l8_counter_limit_per_user_not_global() {
        let counter = WsConnectionCounter::new(2);

        let _g1 = counter.try_acquire("user-1").await.unwrap();
        let _g2 = counter.try_acquire("user-1").await.unwrap();

        // user-1 is full, but user-2 should still work
        assert!(counter.try_acquire("user-1").await.is_err());
        let _g3 = counter.try_acquire("user-2").await.unwrap();
        assert_eq!(counter.count("user-2").await, 1);
    }

    #[tokio::test]
    async fn test_l8_counter_recovers_after_drop() {
        let counter = WsConnectionCounter::new(2);

        let g1 = counter.try_acquire("user-1").await.unwrap();
        let _g2 = counter.try_acquire("user-1").await.unwrap();

        // Full
        assert!(counter.try_acquire("user-1").await.is_err());

        // Drop one guard
        drop(g1);
        assert_eq!(counter.count("user-1").await, 1);

        // Now it should succeed
        let _g3 = counter.try_acquire("user-1").await.unwrap();
        assert_eq!(counter.count("user-1").await, 2);
    }

    #[tokio::test]
    async fn test_l8_counter_raii_on_scope_exit() {
        let counter = WsConnectionCounter::new(10);

        {
            let _g1 = counter.try_acquire("user-1").await.unwrap();
            let _g2 = counter.try_acquire("user-1").await.unwrap();
            assert_eq!(counter.count("user-1").await, 2);
        }
        // Guards dropped at end of scope
        assert_eq!(counter.count("user-1").await, 0);
    }

    #[tokio::test]
    async fn test_l8_counter_error_message_contains_limit() {
        let counter = WsConnectionCounter::new(1);

        let _g = counter.try_acquire("user-1").await.unwrap();

        let err = counter.try_acquire("user-1").await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("1 per user"),
            "L-8: Error message should contain the configured limit, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_l8_counter_total() {
        let counter = WsConnectionCounter::new(10);

        let _g1 = counter.try_acquire("user-a").await.unwrap();
        let _g2 = counter.try_acquire("user-a").await.unwrap();
        let _g3 = counter.try_acquire("user-b").await.unwrap();

        assert_eq!(counter.total().await, 3);
        assert_eq!(counter.count("user-a").await, 2);
        assert_eq!(counter.count("user-b").await, 1);
    }

    #[tokio::test]
    async fn test_l8_counter_clone_shares_state() {
        let counter = WsConnectionCounter::new(10);
        let cloned = counter.clone();

        let _g = counter.try_acquire("user-1").await.unwrap();
        assert_eq!(cloned.count("user-1").await, 1);
    }

    #[tokio::test]
    async fn test_l8_counter_concurrent_acquire() {
        let counter = WsConnectionCounter::new(100);
        let mut handles = Vec::new();

        for i in 0..10 {
            let c = counter.clone();
            handles.push(tokio::spawn(async move {
                let mut guards = Vec::new();
                for j in 0..5 {
                    let g = c.try_acquire(&format!("user-{i}")).await.unwrap();
                    guards.push(g);
                    let _ = j;
                }
                guards // return guards to keep them alive
            }));
        }

        let all_guards: Vec<_> = futures_util::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(counter.total().await, 50);

        drop(all_guards);
        assert_eq!(counter.total().await, 0);
    }

    #[tokio::test]
    async fn test_l8_counter_limit_one() {
        let counter = WsConnectionCounter::new(1);

        let g = counter.try_acquire("user-1").await.unwrap();
        assert!(counter.try_acquire("user-1").await.is_err());

        drop(g);
        let _g2 = counter.try_acquire("user-1").await.unwrap();
    }

    #[tokio::test]
    async fn test_many_users() {
        let registry = UserConnectionRegistry::new();

        let mut receivers = Vec::new();
        for i in 0..50 {
            let (_id, rx) = registry
                .register(&format!("user-{}", i), "hash".to_string())
                .await;
            receivers.push(rx);
        }

        assert_eq!(registry.total_connections().await, 50);

        for i in 0..50 {
            assert_eq!(registry.connection_count(&format!("user-{}", i)).await, 1);
        }
    }
}
