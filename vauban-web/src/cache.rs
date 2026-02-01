/// VAUBAN Web - Cache (Valkey/Redis) connection.
///
/// Provides Redis client for caching and session storage.
/// Supports a no-op mock cache when cache is disabled.
///
/// For Capsicum sandbox mode, connections must be established before
/// entering capability mode. Use `validate_connection()` to verify
/// the connection is working, and `check_or_exit()` for periodic
/// health checks that exit on failure.
use redis::AsyncCommands;
use redis::Client;
use secrecy::ExposeSecret;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// Exit code used when cache connection is lost in sandbox mode.
/// The supervisor will respawn the service when it sees this exit code.
pub const EXIT_CODE_CONNECTION_LOST: i32 = 100;

/// Cache connection enum - can be real Redis or mock.
#[derive(Clone)]
pub enum CacheConnection {
    Redis(Arc<Mutex<redis::aio::MultiplexedConnection>>),
    Mock(Arc<MockCache>),
}

impl CacheConnection {
    /// Validate that the cache connection is working.
    ///
    /// This sends a PING command to Redis and verifies the response.
    /// For mock cache, this always succeeds.
    ///
    /// Call this after creating the cache client but before entering
    /// Capsicum capability mode to ensure the connection is established.
    pub async fn validate_connection(&self) -> AppResult<()> {
        match self {
            CacheConnection::Redis(conn) => {
                let mut conn = conn.lock().await;
                let pong: String = redis::cmd("PING")
                    .query_async(&mut *conn)
                    .await
                    .map_err(AppError::Cache)?;

                if pong != "PONG" {
                    return Err(AppError::Internal(anyhow::anyhow!(
                        "Unexpected PING response from cache: expected 'PONG', got '{}'",
                        pong
                    )));
                }

                tracing::debug!("Cache connection validated (PING/PONG successful)");
                Ok(())
            }
            CacheConnection::Mock(_) => {
                tracing::debug!("Mock cache connection validated (always succeeds)");
                Ok(())
            }
        }
    }

    /// Check if the cache connection is still alive, exit if not (sandbox mode).
    ///
    /// This is designed for Capsicum sandbox mode where the service cannot
    /// recover from a lost cache connection. If the connection check fails,
    /// the process exits with code 100 to trigger a respawn by the supervisor.
    ///
    /// For mock cache, this always succeeds without exiting.
    pub async fn check_or_exit(&self) {
        match self {
            CacheConnection::Redis(conn) => {
                let mut conn = conn.lock().await;
                if let Err(e) = redis::cmd("PING").query_async::<String>(&mut *conn).await {
                    tracing::error!(
                        "Cache connection lost in sandbox mode: {}. Exiting for respawn.",
                        e
                    );
                    std::process::exit(EXIT_CODE_CONNECTION_LOST);
                }
            }
            CacheConnection::Mock(_) => {
                // Mock cache never fails
            }
        }
    }

    /// Check if this is a real Redis connection or a mock.
    pub fn is_redis(&self) -> bool {
        matches!(self, CacheConnection::Redis(_))
    }

    /// Check if this is a mock cache.
    pub fn is_mock(&self) -> bool {
        matches!(self, CacheConnection::Mock(_))
    }
}

/// Mock cache implementation (no-op) for development.
#[derive(Debug, Clone, Default)]
pub struct MockCache;

impl MockCache {
    pub fn new() -> Self {
        Self
    }
}

/// Create a cache client (Redis or mock based on configuration).
pub async fn create_cache_client(config: &Config) -> AppResult<CacheConnection> {
    if !config.cache.enabled {
        warn!("Cache is disabled - using mock cache (no-op)");
        return Ok(CacheConnection::Mock(Arc::new(MockCache::new())));
    }

    // Try to create Redis connection
    match Client::open(config.cache.url.expose_secret()) {
        Ok(client) => match client.get_multiplexed_async_connection().await {
            Ok(manager) => {
                tracing::info!("Cache enabled - connected to Redis/Valkey");
                Ok(CacheConnection::Redis(Arc::new(Mutex::new(manager))))
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to connect to Redis/Valkey - falling back to mock cache"
                );
                Ok(CacheConnection::Mock(Arc::new(MockCache::new())))
            }
        },
        Err(e) => {
            warn!(
                error = %e,
                "Failed to create Redis client - falling back to mock cache"
            );
            Ok(CacheConnection::Mock(Arc::new(MockCache::new())))
        }
    }
}

/// Cache operations trait for type safety.
#[allow(async_fn_in_trait)]
pub trait CacheOps {
    async fn get<T>(&self, key: &str) -> AppResult<Option<T>>
    where
        T: serde::de::DeserializeOwned;

    async fn set<T>(&self, key: &str, value: &T, ttl_secs: Option<u64>) -> AppResult<()>
    where
        T: serde::Serialize;

    async fn delete(&self, key: &str) -> AppResult<()>;

    async fn exists(&self, key: &str) -> AppResult<bool>;
}

impl CacheOps for CacheConnection {
    async fn get<T>(&self, key: &str) -> AppResult<Option<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        match self {
            CacheConnection::Redis(conn) => {
                let mut conn = conn.lock().await;
                let value: Option<String> = conn.get(key).await.map_err(AppError::Cache)?;

                match value {
                    Some(v) => {
                        let deserialized: T = serde_json::from_str(&v).map_err(|e| {
                            AppError::Internal(anyhow::anyhow!("Deserialization error: {}", e))
                        })?;
                        Ok(Some(deserialized))
                    }
                    None => Ok(None),
                }
            }
            CacheConnection::Mock(_) => {
                // Mock cache always returns None (cache miss)
                Ok(None)
            }
        }
    }

    async fn set<T>(&self, key: &str, value: &T, ttl_secs: Option<u64>) -> AppResult<()>
    where
        T: serde::Serialize,
    {
        match self {
            CacheConnection::Redis(conn) => {
                let mut conn = conn.lock().await;
                let serialized = serde_json::to_string(value).map_err(|e| {
                    AppError::Internal(anyhow::anyhow!("Serialization error: {}", e))
                })?;

                if let Some(ttl) = ttl_secs {
                    let _: () = conn
                        .set_ex(key, &serialized, ttl)
                        .await
                        .map_err(AppError::Cache)?;
                } else {
                    let _: () = conn.set(key, &serialized).await.map_err(AppError::Cache)?;
                }

                Ok(())
            }
            CacheConnection::Mock(_) => {
                // Mock cache silently ignores set operations
                Ok(())
            }
        }
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        match self {
            CacheConnection::Redis(conn) => {
                let mut conn = conn.lock().await;
                let _: () = conn.del(key).await.map_err(AppError::Cache)?;
                Ok(())
            }
            CacheConnection::Mock(_) => {
                // Mock cache silently ignores delete operations
                Ok(())
            }
        }
    }

    async fn exists(&self, key: &str) -> AppResult<bool> {
        match self {
            CacheConnection::Redis(conn) => {
                let mut conn = conn.lock().await;
                let result: bool = conn.exists(key).await.map_err(AppError::Cache)?;
                Ok(result)
            }
            CacheConnection::Mock(_) => {
                // Mock cache always returns false (key doesn't exist)
                Ok(false)
            }
        }
    }
}

impl CacheOps for MockCache {
    async fn get<T>(&self, _key: &str) -> AppResult<Option<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        Ok(None)
    }

    async fn set<T>(&self, _key: &str, _value: &T, _ttl_secs: Option<u64>) -> AppResult<()>
    where
        T: serde::Serialize,
    {
        Ok(())
    }

    async fn delete(&self, _key: &str) -> AppResult<()> {
        Ok(())
    }

    async fn exists(&self, _key: &str) -> AppResult<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    // ==================== MockCache Tests ====================

    #[test]
    fn test_mock_cache_new() {
        let cache = MockCache::new();
        // Just verify it can be created
        assert!(std::mem::size_of_val(&cache) == 0); // Zero-sized type
    }

    #[test]
    fn test_mock_cache_clone() {
        let cache = MockCache::new();
        let cloned = cache.clone();
        // Both should be identical ZSTs
        assert!(std::mem::size_of_val(&cloned) == 0);
    }

    #[test]
    fn test_mock_cache_debug() {
        let cache = MockCache::new();
        let debug_str = format!("{:?}", cache);
        assert_eq!(debug_str, "MockCache");
    }

    // ==================== MockCache CacheOps Tests ====================

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestData {
        id: i32,
        name: String,
    }

    #[tokio::test]
    async fn test_mock_cache_get_returns_none() {
        let cache = MockCache::new();
        let result: Option<TestData> = unwrap_ok!(cache.get("any_key").await);
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_mock_cache_get_with_different_keys() {
        let cache = MockCache::new();

        let result1: Option<String> = unwrap_ok!(cache.get("key1").await);
        let result2: Option<i32> = unwrap_ok!(cache.get("key2").await);
        let result3: Option<TestData> = unwrap_ok!(cache.get("key3").await);

        assert!(result1.is_none());
        assert!(result2.is_none());
        assert!(result3.is_none());
    }

    #[tokio::test]
    async fn test_mock_cache_set_succeeds() {
        let cache = MockCache::new();
        let data = TestData {
            id: 1,
            name: "test".to_string(),
        };

        let result = cache.set("test_key", &data, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_cache_set_with_ttl_succeeds() {
        let cache = MockCache::new();
        let data = TestData {
            id: 1,
            name: "test".to_string(),
        };

        let result = cache.set("test_key", &data, Some(3600)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_cache_delete_succeeds() {
        let cache = MockCache::new();

        let result = cache.delete("any_key").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_cache_exists_returns_false() {
        let cache = MockCache::new();

        let result = unwrap_ok!(cache.exists("any_key").await);
        assert!(!result);
    }

    #[tokio::test]
    async fn test_mock_cache_set_then_get_returns_none() {
        // Mock cache doesn't actually store - this verifies behavior
        let cache = MockCache::new();
        let data = TestData {
            id: 42,
            name: "important".to_string(),
        };

        unwrap_ok!(cache.set("my_key", &data, None).await);
        let result: Option<TestData> = unwrap_ok!(cache.get("my_key").await);

        // Mock always returns None even after set
        assert!(result.is_none());
    }

    // ==================== CacheConnection::Mock Tests ====================

    #[tokio::test]
    async fn test_cache_connection_mock_get() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        let result: Option<String> = unwrap_ok!(conn.get("test").await);
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cache_connection_mock_set() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        let result = conn.set("key", &"value", None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cache_connection_mock_delete() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        let result = conn.delete("key").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cache_connection_mock_exists() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        let result = unwrap_ok!(conn.exists("key").await);
        assert!(!result);
    }

    #[tokio::test]
    async fn test_cache_connection_clone() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        let cloned = conn.clone();

        // Both should work independently
        let result1 = unwrap_ok!(conn.exists("key").await);
        let result2 = unwrap_ok!(cloned.exists("key").await);

        assert!(!result1);
        assert!(!result2);
    }

    // ==================== MockCache Additional Tests ====================

    #[test]
    fn test_mock_cache_is_zst() {
        // MockCache should be a zero-sized type
        assert_eq!(std::mem::size_of::<MockCache>(), 0);
    }

    #[tokio::test]
    async fn test_mock_cache_get_primitives() {
        let cache = MockCache::new();

        let str_result: Option<String> = unwrap_ok!(cache.get("key").await);
        let int_result: Option<i64> = unwrap_ok!(cache.get("key").await);
        let bool_result: Option<bool> = unwrap_ok!(cache.get("key").await);

        assert!(str_result.is_none());
        assert!(int_result.is_none());
        assert!(bool_result.is_none());
    }

    #[tokio::test]
    async fn test_mock_cache_set_various_types() {
        let cache = MockCache::new();

        assert!(cache.set("str_key", &"value", None).await.is_ok());
        assert!(cache.set("int_key", &42i64, None).await.is_ok());
        assert!(cache.set("bool_key", &true, None).await.is_ok());
        assert!(cache.set("vec_key", &vec![1, 2, 3], None).await.is_ok());
    }

    #[tokio::test]
    async fn test_mock_cache_operations_idempotent() {
        let cache = MockCache::new();

        // Multiple deletes should all succeed
        for _ in 0..10 {
            assert!(cache.delete("key").await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_mock_cache_exists_always_false() {
        let cache = MockCache::new();

        // Set a value, but exists should still return false
        unwrap_ok!(cache.set("key", &"value", None).await);
        assert!(!unwrap_ok!(cache.exists("key").await));
    }

    // ==================== CacheConnection Pattern Tests ====================

    #[test]
    fn test_cache_connection_mock_construction() {
        let mock = MockCache::new();
        let conn = CacheConnection::Mock(Arc::new(mock));

        match conn {
            CacheConnection::Mock(_) => (),
            _ => panic!("Expected Mock variant"),
        }
    }

    #[tokio::test]
    async fn test_cache_connection_mock_set_with_various_ttl() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));

        // No TTL
        assert!(conn.set("key1", &"value", None).await.is_ok());
        // Short TTL
        assert!(conn.set("key2", &"value", Some(1)).await.is_ok());
        // Long TTL
        assert!(conn.set("key3", &"value", Some(86400)).await.is_ok());
        // Max TTL
        assert!(conn.set("key4", &"value", Some(u64::MAX)).await.is_ok());
    }

    #[tokio::test]
    async fn test_cache_connection_arc_sharing() {
        let mock = Arc::new(MockCache::new());
        let conn1 = CacheConnection::Mock(Arc::clone(&mock));
        let conn2 = CacheConnection::Mock(Arc::clone(&mock));

        // Both connections should work
        assert!(conn1.exists("key").await.is_ok());
        assert!(conn2.exists("key").await.is_ok());
    }

    // ==================== Edge Case Tests ====================

    #[tokio::test]
    async fn test_cache_empty_key() {
        let cache = MockCache::new();
        assert!(cache.get::<String>("").await.is_ok());
        assert!(cache.set("", &"value", None).await.is_ok());
        assert!(cache.delete("").await.is_ok());
        assert!(cache.exists("").await.is_ok());
    }

    #[tokio::test]
    async fn test_cache_long_key() {
        let cache = MockCache::new();
        let long_key = "k".repeat(10000);

        assert!(cache.get::<String>(&long_key).await.is_ok());
        assert!(cache.set(&long_key, &"value", None).await.is_ok());
    }

    #[tokio::test]
    async fn test_cache_unicode_key() {
        let cache = MockCache::new();
        let unicode_key = "键_key_clé_Schlüssel_\u{1F600}";

        assert!(cache.get::<String>(unicode_key).await.is_ok());
        assert!(cache.set(unicode_key, &"value", None).await.is_ok());
    }

    // ==================== Sandbox Mode Tests ====================

    #[test]
    fn test_exit_code_connection_lost_value() {
        assert_eq!(EXIT_CODE_CONNECTION_LOST, 100);
    }

    #[tokio::test]
    async fn test_mock_cache_validate_connection() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        let result = conn.validate_connection().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_cache_check_or_exit() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        // This should not exit for mock cache
        conn.check_or_exit().await;
        // If we reach here, the test passed
    }

    #[test]
    fn test_cache_connection_is_redis() {
        let mock_conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        assert!(!mock_conn.is_redis());
        assert!(mock_conn.is_mock());
    }

    #[test]
    fn test_cache_connection_is_mock() {
        let mock_conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        assert!(mock_conn.is_mock());
        assert!(!mock_conn.is_redis());
    }
}
