/// VAUBAN Web - User WebSocket connections registry.
///
/// Manages individual WebSocket connections with their context (token_hash)
/// to enable personalized messages (e.g., "Current session" indicator).
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
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
        let (conn_id, _receiver) = registry
            .register("user-123", "hash-abc".to_string())
            .await;

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
}
