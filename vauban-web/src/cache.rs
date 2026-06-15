/// VAUBAN Web - In-memory no-op cache.
///
/// Vauban does not depend on any external cache server. This module keeps a
/// minimal, in-process no-op cache abstraction (`CacheConnection` /
/// `MockCache`) so future code can opt into a real in-memory backend without
/// re-introducing a network dependency. Every operation is a no-op today
/// (`get` -> miss, `set`/`delete` -> ignored, `exists` -> false).
use std::sync::Arc;

use tracing::debug;

use crate::config::Config;
use crate::error::AppResult;

/// Cache connection handle.
///
/// Single in-process backend (`Mock`). The enum shape is retained so a real
/// in-memory backend can be added later without churning every construction
/// site, and so `AppState.cache` keeps a stable type.
#[derive(Clone)]
pub enum CacheConnection {
    /// No-op in-memory cache.
    Mock(Arc<MockCache>),
}

impl CacheConnection {
    /// Validate that the cache connection is working.
    ///
    /// The in-memory backend always succeeds (no network involved).
    pub async fn validate_connection(&self) -> AppResult<()> {
        match self {
            CacheConnection::Mock(_) => {
                debug!("In-memory cache validated (always succeeds)");
                Ok(())
            }
        }
    }

    /// Periodic health check hook. The in-memory backend never fails, so this
    /// is a no-op kept for call-site compatibility.
    pub async fn check_or_shutdown(
        &self,
        _server_handle: Option<&axum_server::Handle<std::net::SocketAddr>>,
    ) {
        match self {
            CacheConnection::Mock(_) => {
                // In-memory cache never fails.
            }
        }
    }

    /// Whether this is the in-memory no-op backend (always true today).
    pub fn is_mock(&self) -> bool {
        matches!(self, CacheConnection::Mock(_))
    }
}

/// No-op in-memory cache implementation.
#[derive(Debug, Clone, Default)]
pub struct MockCache;

impl MockCache {
    pub fn new() -> Self {
        Self
    }
}

/// Create the cache client.
///
/// Vauban always uses the in-process no-op cache; no network connection is
/// ever opened (sandbox-friendly). The `config` argument is accepted for
/// signature stability but no longer selects a backend.
pub async fn create_cache_client(_config: &Config) -> AppResult<CacheConnection> {
    debug!("Using in-memory no-op cache");
    Ok(CacheConnection::Mock(Arc::new(MockCache::new())))
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
            CacheConnection::Mock(cache) => cache.get(key).await,
        }
    }

    async fn set<T>(&self, key: &str, value: &T, ttl_secs: Option<u64>) -> AppResult<()>
    where
        T: serde::Serialize,
    {
        match self {
            CacheConnection::Mock(cache) => cache.set(key, value, ttl_secs).await,
        }
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        match self {
            CacheConnection::Mock(cache) => cache.delete(key).await,
        }
    }

    async fn exists(&self, key: &str) -> AppResult<bool> {
        match self {
            CacheConnection::Mock(cache) => cache.exists(key).await,
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
        assert!(std::mem::size_of_val(&cache) == 0); // Zero-sized type
    }

    #[test]
    fn test_mock_cache_clone() {
        let cache = MockCache::new();
        let cloned = cache.clone();
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
    async fn test_mock_cache_set_succeeds() {
        let cache = MockCache::new();
        let data = TestData {
            id: 1,
            name: "test".to_string(),
        };
        assert!(cache.set("test_key", &data, None).await.is_ok());
    }

    #[tokio::test]
    async fn test_mock_cache_set_with_ttl_succeeds() {
        let cache = MockCache::new();
        let data = TestData {
            id: 1,
            name: "test".to_string(),
        };
        assert!(cache.set("test_key", &data, Some(3600)).await.is_ok());
    }

    #[tokio::test]
    async fn test_mock_cache_delete_succeeds() {
        let cache = MockCache::new();
        assert!(cache.delete("any_key").await.is_ok());
    }

    #[tokio::test]
    async fn test_mock_cache_exists_returns_false() {
        let cache = MockCache::new();
        assert!(!unwrap_ok!(cache.exists("any_key").await));
    }

    #[tokio::test]
    async fn test_mock_cache_set_then_get_returns_none() {
        let cache = MockCache::new();
        let data = TestData {
            id: 42,
            name: "important".to_string(),
        };
        unwrap_ok!(cache.set("my_key", &data, None).await);
        let result: Option<TestData> = unwrap_ok!(cache.get("my_key").await);
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
        assert!(conn.set("key", &"value", None).await.is_ok());
    }

    #[tokio::test]
    async fn test_cache_connection_mock_delete() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        assert!(conn.delete("key").await.is_ok());
    }

    #[tokio::test]
    async fn test_cache_connection_mock_exists() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        assert!(!unwrap_ok!(conn.exists("key").await));
    }

    #[tokio::test]
    async fn test_cache_connection_clone() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        let cloned = conn.clone();
        assert!(!unwrap_ok!(conn.exists("key").await));
        assert!(!unwrap_ok!(cloned.exists("key").await));
    }

    #[test]
    fn test_mock_cache_is_zst() {
        assert_eq!(std::mem::size_of::<MockCache>(), 0);
    }

    // ==================== create_cache_client always returns in-memory ====

    #[tokio::test]
    async fn test_create_cache_client_returns_mock_regardless_of_config() {
        // With cache.enabled in either state, the backend is always in-memory:
        // Vauban no longer depends on any external cache server.
        let base = crate::config::test_fixtures::base_config();
        let testing = crate::config::test_fixtures::testing_config();
        let mut config = unwrap_ok!(Config::from_toml_with_overlay(base, testing));

        config.cache.enabled = false;
        assert!(unwrap_ok!(create_cache_client(&config).await).is_mock());

        config.cache.enabled = true;
        assert!(
            unwrap_ok!(create_cache_client(&config).await).is_mock(),
            "cache.enabled = true must still yield the in-memory backend (no network)"
        );
    }

    // ==================== Sandbox / no-network guarantees ====================

    /// Return only the production (non-test) portion of cache.rs source.
    fn cache_prod_source() -> &'static str {
        let full = include_str!("cache.rs");
        full.split("#[cfg(test)]").next().unwrap_or(full)
    }

    #[test]
    fn test_source_opens_no_network_connection() {
        // Structural guard: the cache must never open a socket. No external
        // cache crate import, no connection opener.
        let source = cache_prod_source();
        assert!(
            !source.contains("get_multiplexed_async_connection"),
            "cache.rs must not open any network connection"
        );
        assert!(
            !source.contains("::Client"),
            "cache.rs must not construct an external cache client"
        );
    }

    #[tokio::test]
    async fn test_mock_cache_validate_connection() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        assert!(conn.validate_connection().await.is_ok());
    }

    #[tokio::test]
    async fn test_mock_cache_check_or_shutdown() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        conn.check_or_shutdown(None).await;
    }

    #[test]
    fn test_cache_connection_is_mock() {
        let conn = CacheConnection::Mock(Arc::new(MockCache::new()));
        assert!(conn.is_mock());
    }

    #[tokio::test]
    async fn test_mock_cache_clone_independent() {
        let conn1 = CacheConnection::Mock(Arc::new(MockCache::new()));
        let conn2 = conn1.clone();
        unwrap_ok!(conn1.set("key", &"value", None).await);
        let result: Option<String> = unwrap_ok!(conn2.get("key").await);
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cache_edge_case_keys() {
        let cache = MockCache::new();
        assert!(cache.get::<String>("").await.is_ok());
        assert!(cache.set("", &"value", None).await.is_ok());
        let long_key = "k".repeat(10000);
        assert!(cache.set(&long_key, &"value", None).await.is_ok());
        let unicode_key = "键_key_clé_Schlüssel_\u{1F600}";
        assert!(cache.set(unicode_key, &"value", None).await.is_ok());
    }
}
