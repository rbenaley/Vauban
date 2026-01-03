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

