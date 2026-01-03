/// VAUBAN Web - Cache (Valkey/Redis) connection.
///
/// Provides Redis client for caching and session storage.
/// Supports a no-op mock cache when cache is disabled.

use redis::Client;
use redis::AsyncCommands;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// Cache connection enum - can be real Redis or mock.
#[derive(Clone)]
pub enum CacheConnection {
    Redis(Arc<Mutex<redis::aio::MultiplexedConnection>>),
    Mock(Arc<MockCache>),
}

/// Mock cache implementation (no-op) for development.
#[derive(Debug, Clone)]
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
    match Client::open(config.cache.url.as_str()) {
        Ok(client) => {
            match client.get_multiplexed_async_connection().await {
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
            }
        }
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
                let value: Option<String> = conn.get(key).await
                    .map_err(|e| AppError::Cache(e))?;

                match value {
                    Some(v) => {
                        let deserialized: T = serde_json::from_str(&v)
                            .map_err(|e| AppError::Internal(anyhow::anyhow!("Deserialization error: {}", e)))?;
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
                let serialized = serde_json::to_string(value)
                    .map_err(|e| AppError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;

                if let Some(ttl) = ttl_secs {
                    let _: () = conn.set_ex(key, &serialized, ttl as u64).await
                        .map_err(|e| AppError::Cache(e))?;
                } else {
                    let _: () = conn.set(key, &serialized).await
                        .map_err(|e| AppError::Cache(e))?;
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
                let _: () = conn.del(key).await
                    .map_err(|e| AppError::Cache(e))?;
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
                let result: bool = conn.exists(key).await
                    .map_err(|e| AppError::Cache(e))?;
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
        let result: Option<TestData> = cache.get("any_key").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_mock_cache_get_with_different_keys() {
        let cache = MockCache::new();
        
        let result1: Option<String> = cache.get("key1").await.unwrap();
        let result2: Option<i32> = cache.get("key2").await.unwrap();
        let result3: Option<TestData> = cache.get("key3").await.unwrap();
        
        assert!(result1.is_none());
        assert!(result2.is_none());
        assert!(result3.is_none());
    }

    #[tokio::test]
    async fn test_mock_cache_set_succeeds() {
        let cache = MockCache::new();
        let data = TestData { id: 1, name: "test".to_string() };
        
        let result = cache.set("test_key", &data, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_cache_set_with_ttl_succeeds() {
        let cache = MockCache::new();
        let data = TestData { id: 1, name: "test".to_string() };
        
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
        
        let result = cache.exists("any_key").await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_mock_cache_set_then_get_returns_none() {
        // Mock cache doesn't actually store - this verifies behavior
        let cache = MockCache::new();
        let data = TestData { id: 42, name: "important".to_string() };
        
        cache.set("my_key", &data, None).await.unwrap();
        let result: Option<TestData> = cache.get("my_key").await.unwrap();
        
        // Mock always returns None even after set
        assert!(result.is_none());
    }

    // ==================== CacheConnection::Mock Tests ====================

    #[tokio::test]
    async fn test_cache_connection_mock_get() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        let result: Option<String> = conn.get("test").await.unwrap();
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
        let result = conn.exists("key").await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_cache_connection_clone() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        let cloned = conn.clone();
        
        // Both should work independently
        let result1 = conn.exists("key").await.unwrap();
        let result2 = cloned.exists("key").await.unwrap();
        
        assert!(!result1);
        assert!(!result2);
    }
}

