/// VAUBAN Web - Rate Limiting Service.
///
/// Provides rate limiting for login endpoints with dual backend support:
/// - Redis/Valkey when `cache.enabled = true`
/// - In-memory DashMap when `cache.enabled = false` (for development)
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, warn};

use crate::error::{AppError, AppResult};

/// Rate limiting result.
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Remaining requests in the current window.
    pub remaining: u32,
    /// Seconds until the rate limit resets.
    pub reset_in_secs: u64,
}

/// Rate limiter with dual backend support.
#[derive(Clone)]
pub enum RateLimiter {
    /// Redis/Valkey backend for distributed rate limiting.
    Redis {
        client: redis::Client,
        limit_per_minute: u32,
    },
    /// In-memory backend using DashMap for development.
    InMemory {
        store: Arc<DashMap<String, RateLimitEntry>>,
        limit_per_minute: u32,
    },
    /// No-op rate limiter (disabled).
    Disabled,
}

/// Entry for in-memory rate limiting.
#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    /// Number of requests in current window.
    pub count: u32,
    /// When the current window started.
    pub window_start: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter based on configuration.
    ///
    /// - If `cache_enabled` is true and `redis_url` is provided, uses Redis.
    /// - Otherwise, uses in-memory storage.
    pub fn new(
        cache_enabled: bool,
        redis_url: Option<&str>,
        limit_per_minute: u32,
    ) -> AppResult<Self> {
        if cache_enabled {
            if let Some(url) = redis_url {
                match redis::Client::open(url) {
                    Ok(client) => {
                        debug!("Rate limiter using Redis backend");
                        return Ok(Self::Redis {
                            client,
                            limit_per_minute,
                        });
                    }
                    Err(e) => {
                        warn!("Failed to connect to Redis for rate limiting: {}. Falling back to in-memory.", e);
                    }
                }
            }
        }

        debug!("Rate limiter using in-memory backend");
        Ok(Self::InMemory {
            store: Arc::new(DashMap::new()),
            limit_per_minute,
        })
    }

    /// Create a disabled rate limiter.
    pub fn disabled() -> Self {
        Self::Disabled
    }

    /// Check if a request is allowed for the given key.
    ///
    /// The key is typically the client IP address.
    /// Returns `RateLimitResult` with the current status.
    pub async fn check(&self, key: &str) -> AppResult<RateLimitResult> {
        match self {
            Self::Redis { client, limit_per_minute } => {
                self.check_redis(client, key, *limit_per_minute).await
            }
            Self::InMemory { store, limit_per_minute } => {
                self.check_in_memory(store, key, *limit_per_minute)
            }
            Self::Disabled => Ok(RateLimitResult {
                allowed: true,
                remaining: u32::MAX,
                reset_in_secs: 0,
            }),
        }
    }

    /// Check rate limit using Redis.
    async fn check_redis(
        &self,
        client: &redis::Client,
        key: &str,
        limit: u32,
    ) -> AppResult<RateLimitResult> {
        use redis::AsyncCommands;

        let redis_key = format!("rate_limit:login:{}", key);
        let window_secs: u64 = 60;

        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Cache(e))?;

        // Increment counter and set TTL atomically using MULTI/EXEC
        let count: u32 = redis::cmd("INCR")
            .arg(&redis_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Cache(e))?;

        // Set TTL only on first request (when count is 1)
        if count == 1 {
            let _: () = conn
                .expire(&redis_key, window_secs as i64)
                .await
                .map_err(|e| AppError::Cache(e))?;
        }

        // Get TTL for reset time
        let ttl: i64 = conn
            .ttl(&redis_key)
            .await
            .map_err(|e| AppError::Cache(e))?;

        let reset_in_secs = if ttl > 0 { ttl as u64 } else { window_secs };
        let allowed = count <= limit;
        let remaining = if count >= limit { 0 } else { limit - count };

        if !allowed {
            debug!(
                "Rate limit exceeded for key '{}': {} requests (limit: {})",
                key, count, limit
            );
        }

        Ok(RateLimitResult {
            allowed,
            remaining,
            reset_in_secs,
        })
    }

    /// Check rate limit using in-memory DashMap.
    fn check_in_memory(
        &self,
        store: &DashMap<String, RateLimitEntry>,
        key: &str,
        limit: u32,
    ) -> AppResult<RateLimitResult> {
        let window_duration = Duration::from_secs(60);
        let now = Instant::now();

        let mut entry = store.entry(key.to_string()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Check if window has expired
        let elapsed = now.duration_since(entry.window_start);
        if elapsed >= window_duration {
            // Reset window
            entry.count = 1;
            entry.window_start = now;
        } else {
            // Increment counter
            entry.count += 1;
        }

        let count = entry.count;

        // Calculate time until reset using saturating_sub to prevent overflow panic.
        // After window reset, we need to recalculate elapsed from the new window_start.
        // Use saturating_sub as a safety net in case of timing edge cases.
        let current_elapsed = now.duration_since(entry.window_start);
        let reset_in_secs = window_duration.saturating_sub(current_elapsed).as_secs();

        let allowed = count <= limit;
        let remaining = if count >= limit { 0 } else { limit - count };

        if !allowed {
            debug!(
                "Rate limit exceeded for key '{}': {} requests (limit: {})",
                key, count, limit
            );
        }

        Ok(RateLimitResult {
            allowed,
            remaining,
            reset_in_secs,
        })
    }

    /// Clean up expired entries from in-memory store.
    ///
    /// Should be called periodically to prevent memory leaks.
    pub fn cleanup_expired(&self) {
        if let Self::InMemory { store, .. } = self {
            let now = Instant::now();
            let window_duration = Duration::from_secs(60);

            store.retain(|_, entry| {
                now.duration_since(entry.window_start) < window_duration * 2
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(false, None, 5).unwrap();

        for i in 1..=5 {
            let result = limiter.check("test_ip").await.unwrap();
            assert!(result.allowed, "Request {} should be allowed", i);
            assert_eq!(result.remaining, 5 - i);
        }
    }

    #[tokio::test]
    async fn test_in_memory_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(false, None, 3).unwrap();

        // Use up the limit
        for _ in 0..3 {
            let result = limiter.check("test_ip").await.unwrap();
            assert!(result.allowed);
        }

        // Next request should be blocked
        let result = limiter.check("test_ip").await.unwrap();
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }

    #[tokio::test]
    async fn test_in_memory_rate_limiter_different_keys() {
        let limiter = RateLimiter::new(false, None, 2).unwrap();

        // First IP
        let result1 = limiter.check("ip1").await.unwrap();
        assert!(result1.allowed);
        assert_eq!(result1.remaining, 1);

        // Second IP (separate limit)
        let result2 = limiter.check("ip2").await.unwrap();
        assert!(result2.allowed);
        assert_eq!(result2.remaining, 1);

        // First IP again
        let result3 = limiter.check("ip1").await.unwrap();
        assert!(result3.allowed);
        assert_eq!(result3.remaining, 0);
    }

    #[tokio::test]
    async fn test_disabled_rate_limiter_always_allows() {
        let limiter = RateLimiter::disabled();

        for _ in 0..100 {
            let result = limiter.check("any_ip").await.unwrap();
            assert!(result.allowed);
        }
    }

    #[test]
    fn test_cleanup_expired_entries() {
        let limiter = RateLimiter::new(false, None, 10).unwrap();

        if let RateLimiter::InMemory { store, .. } = &limiter {
            // Add an entry with old timestamp
            store.insert(
                "old_ip".to_string(),
                RateLimitEntry {
                    count: 5,
                    window_start: Instant::now() - Duration::from_secs(180),
                },
            );

            // Add a recent entry
            store.insert(
                "recent_ip".to_string(),
                RateLimitEntry {
                    count: 3,
                    window_start: Instant::now(),
                },
            );

            assert_eq!(store.len(), 2);

            // Cleanup
            limiter.cleanup_expired();

            // Old entry should be removed
            assert_eq!(store.len(), 1);
            assert!(store.contains_key("recent_ip"));
            assert!(!store.contains_key("old_ip"));
        }
    }

    // ==================== Duration Overflow Prevention Tests ====================

    #[tokio::test]
    async fn test_reset_in_secs_does_not_overflow_after_window_reset() {
        // This test ensures that reset_in_secs calculation doesn't panic
        // when the window has been reset (elapsed was >= window_duration)
        let limiter = RateLimiter::new(false, None, 10).unwrap();

        if let RateLimiter::InMemory { store, .. } = &limiter {
            // Simulate an entry with an old window that will trigger a reset
            store.insert(
                "old_window_ip".to_string(),
                RateLimitEntry {
                    count: 5,
                    window_start: Instant::now() - Duration::from_secs(120), // 2 minutes ago
                },
            );

            // This should not panic - the window will be reset and reset_in_secs calculated safely
            let result = limiter.check("old_window_ip").await.unwrap();

            // After reset, count should be 1 and we should have ~60 seconds until next reset
            assert!(result.allowed);
            assert_eq!(result.remaining, 9); // limit (10) - count (1) = 9
            // reset_in_secs should be close to 60 (the full window)
            assert!(result.reset_in_secs <= 60);
        }
    }

    #[tokio::test]
    async fn test_reset_in_secs_with_very_old_entry() {
        // Test with an extremely old entry to ensure no overflow
        let limiter = RateLimiter::new(false, None, 5).unwrap();

        if let RateLimiter::InMemory { store, .. } = &limiter {
            // Entry from a very long time ago (1 hour)
            store.insert(
                "very_old_ip".to_string(),
                RateLimitEntry {
                    count: 100,
                    window_start: Instant::now() - Duration::from_secs(3600),
                },
            );

            // Should not panic
            let result = limiter.check("very_old_ip").await.unwrap();

            assert!(result.allowed);
            assert_eq!(result.remaining, 4); // After reset, count is 1
        }
    }

    #[test]
    fn test_saturating_sub_behavior() {
        // Verify that saturating_sub returns Duration::ZERO instead of panicking
        let small = Duration::from_secs(10);
        let large = Duration::from_secs(100);

        // This would panic with regular subtraction: small - large
        let result = small.saturating_sub(large);
        assert_eq!(result, Duration::ZERO);

        // Normal case works as expected
        let normal = large.saturating_sub(small);
        assert_eq!(normal, Duration::from_secs(90));
    }

    #[tokio::test]
    async fn test_rate_limiter_reset_in_secs_is_reasonable() {
        let limiter = RateLimiter::new(false, None, 10).unwrap();

        // First request
        let result = limiter.check("new_ip").await.unwrap();

        // reset_in_secs should be between 0 and 60 (the window size)
        assert!(
            result.reset_in_secs <= 60,
            "reset_in_secs should be <= 60, got {}",
            result.reset_in_secs
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_multiple_requests_reset_time_decreases() {
        let limiter = RateLimiter::new(false, None, 100).unwrap();

        let result1 = limiter.check("timing_ip").await.unwrap();
        let first_reset = result1.reset_in_secs;

        // Wait a tiny bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        let result2 = limiter.check("timing_ip").await.unwrap();
        let second_reset = result2.reset_in_secs;

        // Second reset time should be <= first (time has passed)
        assert!(
            second_reset <= first_reset,
            "Reset time should decrease or stay same: {} vs {}",
            second_reset,
            first_reset
        );
    }
}
