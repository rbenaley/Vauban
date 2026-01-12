/// VAUBAN Web - User WebSocket connections registry.
///
/// Manages individual WebSocket connections with their context (token_hash)
/// to enable personalized messages (e.g., "Current session" indicator).
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, warn};
use uuid::Uuid;

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

    /// Register a new connection for a user.
    /// Returns a receiver that the WebSocket handler should listen to.
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
            "Registered new WebSocket connection"
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
        let msg1 = rx1.recv().await.unwrap();
        let msg2 = rx2.recv().await.unwrap();

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
    async fn test_registry_default() {
        let registry = UserConnectionRegistry::default();
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

        let msg1 = rx1.recv().await.unwrap();
        let msg2 = rx2.recv().await.unwrap();

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
            let msg = rx.recv().await.unwrap();
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

        let msg = rx.recv().await.unwrap();
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
            for i in 0..10 {
                let (_id, _rx) = registry_clone
                    .register("user-1", format!("hash-{}", i))
                    .await;
            }
        });

        let registry_clone2 = registry.clone();
        let handle2 = tokio::spawn(async move {
            for i in 10..20 {
                let (_id, _rx) = registry_clone2
                    .register("user-1", format!("hash-{}", i))
                    .await;
            }
        });

        handle1.await.unwrap();
        handle2.await.unwrap();

        assert_eq!(registry.connection_count("user-1").await, 20);
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
        let msg = rx2.recv().await.unwrap();
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
        for i in 0..100 {
            let (_id, rx) = registry.register("user-1", format!("hash-{}", i)).await;
            receivers.push(rx);
        }

        assert_eq!(registry.connection_count("user-1").await, 100);
        assert_eq!(registry.total_connections().await, 100);
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
