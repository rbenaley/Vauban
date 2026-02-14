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
///
/// # Fail-closed behavior (M-2)
///
/// When `cache.enabled = true`, Redis **must** be reachable.  If the client
/// cannot be created or the connection fails, an error is returned instead of
/// silently falling back to a no-op mock.  This prevents rate limiting from
/// being silently disabled in production.
///
/// When `cache.enabled = false`, a [`MockCache`] is returned (explicit choice
/// by the administrator, not a silent fallback).
pub async fn create_cache_client(config: &Config) -> AppResult<CacheConnection> {
    if !config.cache.enabled {
        warn!("Cache is disabled - using mock cache (no-op)");
        return Ok(CacheConnection::Mock(Arc::new(MockCache::new())));
    }

    // cache.enabled = true -> Redis MUST be available (fail-closed, M-2).
    let client = Client::open(config.cache.url.expose_secret()).map_err(|e| {
        AppError::Config(format!(
            "Cache is enabled but Redis client creation failed: {}. \
             Set cache.enabled = false to run without cache.",
            e
        ))
    })?;

    let manager = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| {
            AppError::Config(format!(
                "Cache is enabled but cannot connect to Redis/Valkey: {}. \
                 Set cache.enabled = false to run without cache.",
                e
            ))
        })?;

    tracing::info!("Cache enabled - connected to Redis/Valkey");
    Ok(CacheConnection::Redis(Arc::new(Mutex::new(manager))))
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

    // ==================== M-2: Fail-closed cache creation tests ====================

    /// Helper: build a Config with specific cache settings.
    fn config_with_cache(url: &str, enabled: bool) -> Config {
        let base = crate::config::test_fixtures::base_config();
        let testing = crate::config::test_fixtures::testing_config();
        let mut config = unwrap_ok!(Config::from_toml_with_overlay(base, testing));
        config.cache.enabled = enabled;
        config.cache.url = secrecy::SecretString::from(url.to_string());
        config
    }

    #[tokio::test]
    async fn test_m2_cache_disabled_returns_mock() {
        // When cache.enabled = false, a MockCache must be returned (no error).
        // This is the current dev/testing path and must never break.
        let config = config_with_cache("redis://localhost:6379", false);
        assert!(!config.cache.enabled);

        let result = create_cache_client(&config).await;
        let cache = unwrap_ok!(result);
        assert!(
            cache.is_mock(),
            "cache.enabled = false must return MockCache"
        );
    }

    #[tokio::test]
    async fn test_m2_cache_enabled_invalid_url_returns_error() {
        // When cache.enabled = true but the URL is unreachable, the function
        // must return an error (fail-closed), NOT a silent MockCache fallback.
        let config = config_with_cache(
            "redis://invalid-host-that-does-not-exist:9999",
            true,
        );
        assert!(config.cache.enabled);

        let result = create_cache_client(&config).await;
        let err = match result {
            Err(e) => e,
            Ok(ref c) => panic!(
                "cache.enabled = true + unreachable Redis must return Err, got Ok({})",
                if c.is_mock() { "Mock" } else { "Redis" }
            ),
        };

        let err_msg = format!("{}", err);
        assert!(
            err_msg.contains("Cache is enabled"),
            "Error message should mention 'Cache is enabled', got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_m2_cache_enabled_bad_scheme_returns_error() {
        // A malformed URL scheme must also fail, not silently fallback.
        let config = config_with_cache("not-a-valid-redis-url", true);

        let result = create_cache_client(&config).await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("cache.enabled = true + bad URL scheme must return Err"),
        };

        let err_msg = format!("{}", err);
        assert!(
            err_msg.contains("cache.enabled = false"),
            "Error message should suggest setting cache.enabled = false, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_m2_cache_disabled_with_bad_url_still_returns_mock() {
        // Even with a garbage URL, cache.enabled = false must return MockCache.
        // The URL is never contacted.
        let config = config_with_cache("completely-invalid-garbage", false);

        let cache = unwrap_ok!(create_cache_client(&config).await);
        assert!(
            cache.is_mock(),
            "cache.enabled = false must return MockCache regardless of URL"
        );
    }
}
