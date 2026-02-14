/// VAUBAN Web - Rate Limiting Service.
///
/// Provides rate limiting for login endpoints with dual backend support:
/// - Redis/Valkey when `cache.enabled = true`
/// - In-memory DashMap when `cache.enabled = false` (for development)
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::debug;

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
    /// # Fail-closed behavior (M-2)
    ///
    /// - If `cache_enabled` is true and `redis_url` is provided, the Redis
    ///   client **must** be created successfully.  On failure an error is
    ///   returned instead of silently falling back to in-memory.
    /// - If `cache_enabled` is false, in-memory storage is used (explicit
    ///   choice by the administrator).
    pub fn new(
        cache_enabled: bool,
        redis_url: Option<&str>,
        limit_per_minute: u32,
    ) -> AppResult<Self> {
        if cache_enabled {
            if let Some(url) = redis_url {
                // cache_enabled = true -> Redis MUST work (fail-closed, M-2).
                let client = redis::Client::open(url).map_err(|e| {
                    AppError::Config(format!(
                        "Rate limiter: cache is enabled but Redis client creation failed: {}. \
                         Set cache.enabled = false to use in-memory rate limiting.",
                        e
                    ))
                })?;
                debug!("Rate limiter using Redis backend");
                return Ok(Self::Redis {
                    client,
                    limit_per_minute,
                });
            }
            // cache_enabled = true but no URL provided -> configuration error.
            return Err(AppError::Config(
                "Rate limiter: cache is enabled but no Redis URL provided. \
                 Set cache.url or set cache.enabled = false."
                    .to_string(),
            ));
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
            Self::Redis {
                client,
                limit_per_minute,
            } => self.check_redis(client, key, *limit_per_minute).await,
            Self::InMemory {
                store,
                limit_per_minute,
            } => self.check_in_memory(store, key, *limit_per_minute),
            Self::Disabled => Ok(RateLimitResult {
                allowed: true,
                remaining: u32::MAX,
                reset_in_secs: 0,
            }),
        }
    }

    /// Lua script for atomic rate limiting (M-6).
    ///
    /// Executes INCR and TTL management in a single atomic operation on the
    /// Redis server, preventing the race condition where a crash between INCR
    /// and EXPIRE could leave a key without a TTL (permanently blocking an IP).
    ///
    /// The script also recovers stale keys: if a key somehow exists without a
    /// TTL (e.g. leftover from the old non-atomic code), it sets one.
    ///
    /// KEYS[1] = rate limit key
    /// ARGV[1] = window size in seconds
    ///
    /// Returns: { count, ttl }
    const RATE_LIMIT_LUA: &'static str = r#"
local count = redis.call('INCR', KEYS[1])
local ttl   = redis.call('TTL',  KEYS[1])
if ttl == -1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
    ttl = tonumber(ARGV[1])
end
return { count, ttl }
"#;

    /// Check rate limit using Redis with an atomic Lua script (M-6).
    async fn check_redis(
        &self,
        client: &redis::Client,
        key: &str,
        limit: u32,
    ) -> AppResult<RateLimitResult> {
        let redis_key = format!("rate_limit:login:{}", key);
        let window_secs: u64 = 60;

        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(AppError::Cache)?;

        // Execute the atomic Lua script: INCR + conditional EXPIRE in one call.
        let (count, ttl): (u32, i64) = redis::Script::new(Self::RATE_LIMIT_LUA)
            .key(&redis_key)
            .arg(window_secs)
            .invoke_async(&mut conn)
            .await
            .map_err(AppError::Cache)?;

        let reset_in_secs = if ttl > 0 { ttl as u64 } else { window_secs };
        let allowed = count <= limit;
        let remaining = limit.saturating_sub(count);

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
        let remaining = limit.saturating_sub(count);

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

            // Count entries before cleanup for metrics
            let before_count = store.len();

            store.retain(|_, entry| now.duration_since(entry.window_start) < window_duration * 2);

            let expired_count = before_count.saturating_sub(store.len());
            if expired_count > 0 {
                debug!("Cleaned up {} expired rate limit entries", expired_count);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_rate_limiter_allows_within_limit() {
        let limiter = unwrap_ok!(RateLimiter::new(false, None, 5));

        for i in 1..=5 {
            let result = unwrap_ok!(limiter.check("test_ip").await);
            assert!(result.allowed, "Request {} should be allowed", i);
            assert_eq!(result.remaining, 5 - i);
        }
    }

    #[tokio::test]
    async fn test_in_memory_rate_limiter_blocks_over_limit() {
        let limiter = unwrap_ok!(RateLimiter::new(false, None, 3));

        // Use up the limit
        for _ in 0..3 {
            let result = unwrap_ok!(limiter.check("test_ip").await);
            assert!(result.allowed);
        }

        // Next request should be blocked
        let result = unwrap_ok!(limiter.check("test_ip").await);
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }

    #[tokio::test]
    async fn test_in_memory_rate_limiter_different_keys() {
        let limiter = unwrap_ok!(RateLimiter::new(false, None, 2));

        // First IP
        let result1 = unwrap_ok!(limiter.check("ip1").await);
        assert!(result1.allowed);
        assert_eq!(result1.remaining, 1);

        // Second IP (separate limit)
        let result2 = unwrap_ok!(limiter.check("ip2").await);
        assert!(result2.allowed);
        assert_eq!(result2.remaining, 1);

        // First IP again
        let result3 = unwrap_ok!(limiter.check("ip1").await);
        assert!(result3.allowed);
        assert_eq!(result3.remaining, 0);
    }

    #[tokio::test]
    async fn test_disabled_rate_limiter_always_allows() {
        let limiter = RateLimiter::disabled();

        for _ in 0..100 {
            let result = unwrap_ok!(limiter.check("any_ip").await);
            assert!(result.allowed);
        }
    }

    #[test]
    fn test_cleanup_expired_entries() {
        let limiter = unwrap_ok!(RateLimiter::new(false, None, 10));

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
        let limiter = unwrap_ok!(RateLimiter::new(false, None, 10));

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
            let result = unwrap_ok!(limiter.check("old_window_ip").await);

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
        let limiter = unwrap_ok!(RateLimiter::new(false, None, 5));

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
            let result = unwrap_ok!(limiter.check("very_old_ip").await);

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
        let limiter = unwrap_ok!(RateLimiter::new(false, None, 10));

        // First request
        let result = unwrap_ok!(limiter.check("new_ip").await);

        // reset_in_secs should be between 0 and 60 (the window size)
        assert!(
            result.reset_in_secs <= 60,
            "reset_in_secs should be <= 60, got {}",
            result.reset_in_secs
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_multiple_requests_reset_time_decreases() {
        let limiter = unwrap_ok!(RateLimiter::new(false, None, 100));

        let result1 = unwrap_ok!(limiter.check("timing_ip").await);
        let first_reset = result1.reset_in_secs;

        // Wait a tiny bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        let result2 = unwrap_ok!(limiter.check("timing_ip").await);
        let second_reset = result2.reset_in_secs;

        // Second reset time should be <= first (time has passed)
        assert!(
            second_reset <= first_reset,
            "Reset time should decrease or stay same: {} vs {}",
            second_reset,
            first_reset
        );
    }

    // ==================== M-2: Fail-closed rate limiter tests ====================

    #[test]
    fn test_m2_cache_disabled_returns_in_memory() {
        // When cache_enabled = false, the rate limiter must use InMemory.
        // This is the current dev/testing path and must never break.
        let limiter = unwrap_ok!(RateLimiter::new(false, None, 10));
        assert!(
            matches!(limiter, RateLimiter::InMemory { .. }),
            "cache_enabled = false must return InMemory rate limiter"
        );
    }

    #[test]
    fn test_m2_cache_disabled_with_url_returns_in_memory() {
        // Even when a URL is provided, cache_enabled = false -> InMemory.
        let limiter = unwrap_ok!(RateLimiter::new(
            false,
            Some("redis://localhost:6379"),
            10
        ));
        assert!(
            matches!(limiter, RateLimiter::InMemory { .. }),
            "cache_enabled = false must return InMemory even with a URL"
        );
    }

    #[test]
    fn test_m2_cache_enabled_valid_url_returns_redis() {
        // cache_enabled = true + valid URL format -> Redis variant.
        // Note: Client::open only validates the URL format, it does not
        // actually connect (that happens in check_redis).
        let limiter = unwrap_ok!(RateLimiter::new(
            true,
            Some("redis://localhost:6379"),
            10
        ));
        assert!(
            matches!(limiter, RateLimiter::Redis { .. }),
            "cache_enabled = true + valid URL must return Redis rate limiter"
        );
    }

    #[test]
    fn test_m2_cache_enabled_bad_url_returns_error() {
        // cache_enabled = true + malformed URL -> error (fail-closed).
        let result = RateLimiter::new(true, Some("not-a-valid-redis-url"), 10);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("cache_enabled = true + bad URL must return Err"),
        };

        let err_msg = format!("{}", err);
        assert!(
            err_msg.contains("cache is enabled"),
            "Error message should mention 'cache is enabled', got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("cache.enabled = false"),
            "Error message should suggest setting cache.enabled = false, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_m2_cache_enabled_no_url_returns_error() {
        // cache_enabled = true but no URL -> error (fail-closed).
        let result = RateLimiter::new(true, None, 10);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("cache_enabled = true + no URL must return Err"),
        };

        let err_msg = format!("{}", err);
        assert!(
            err_msg.contains("no Redis URL"),
            "Error message should mention 'no Redis URL', got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_m2_in_memory_rate_limiter_still_functional() {
        // Regression: after M-2 fix, the in-memory backend must still work.
        let limiter = unwrap_ok!(RateLimiter::new(false, None, 3));

        // Use up the limit
        for i in 1..=3 {
            let result = unwrap_ok!(limiter.check("regression_ip").await);
            assert!(result.allowed, "Request {} should be allowed", i);
        }

        // Next request should be blocked
        let result = unwrap_ok!(limiter.check("regression_ip").await);
        assert!(!result.allowed, "Request 4 should be blocked");
        assert_eq!(result.remaining, 0);
    }

    // ==================== M-6: Atomic Lua script tests ====================

    #[test]
    fn test_m6_lua_script_contains_atomic_incr_and_expire() {
        // The Lua script must contain INCR and EXPIRE in a single script
        // so they execute atomically on the Redis server.
        let lua = RateLimiter::RATE_LIMIT_LUA;
        assert!(
            lua.contains("redis.call('INCR'"),
            "M-6: Lua script must call INCR"
        );
        assert!(
            lua.contains("redis.call('EXPIRE'"),
            "M-6: Lua script must call EXPIRE"
        );
        assert!(
            lua.contains("redis.call('TTL'"),
            "M-6: Lua script must call TTL to check key expiry"
        );
    }

    #[test]
    fn test_m6_lua_script_handles_missing_ttl() {
        // The script must detect keys without TTL (ttl == -1) and set one.
        // This handles both first-request and crash-recovery scenarios.
        let lua = RateLimiter::RATE_LIMIT_LUA;
        assert!(
            lua.contains("ttl == -1"),
            "M-6: Lua script must detect missing TTL (ttl == -1) for crash recovery"
        );
    }

    #[test]
    fn test_m6_lua_script_returns_count_and_ttl() {
        // The script must return both count and ttl so the Rust code
        // can compute allowed/remaining/reset_in_secs.
        let lua = RateLimiter::RATE_LIMIT_LUA;
        assert!(
            lua.contains("return { count, ttl }") || lua.contains("return {count, ttl}"),
            "M-6: Lua script must return {{ count, ttl }}"
        );
    }

    #[test]
    fn test_m6_lua_script_uses_keys_and_argv() {
        // The script must use KEYS[1] for the rate limit key and
        // ARGV[1] for the window size, following Redis best practices.
        let lua = RateLimiter::RATE_LIMIT_LUA;
        assert!(
            lua.contains("KEYS[1]"),
            "M-6: Lua script must use KEYS[1] for the rate limit key"
        );
        assert!(
            lua.contains("ARGV[1]"),
            "M-6: Lua script must use ARGV[1] for the window size"
        );
    }

    #[test]
    fn test_m6_lua_script_is_valid_redis_script() {
        // redis::Script::new() accepts the Lua code and computes a SHA1 hash.
        // A non-empty hash confirms the script is structurally accepted by the
        // redis crate (actual Lua syntax is validated server-side).
        let script = redis::Script::new(RateLimiter::RATE_LIMIT_LUA);
        let hash = script.get_hash();
        assert!(
            !hash.is_empty(),
            "M-6: redis::Script must produce a non-empty SHA1 hash"
        );
        assert_eq!(
            hash.len(),
            40,
            "M-6: SHA1 hash should be 40 hex chars, got {}",
            hash.len()
        );
    }

    #[test]
    fn test_m6_lua_script_hash_is_stable() {
        // The Lua script hash must be stable across invocations (same code
        // produces same hash).  This ensures EVALSHA caching works correctly.
        let script1 = redis::Script::new(RateLimiter::RATE_LIMIT_LUA);
        let script2 = redis::Script::new(RateLimiter::RATE_LIMIT_LUA);
        assert_eq!(
            script1.get_hash(),
            script2.get_hash(),
            "M-6: Lua script hash must be stable across invocations"
        );
    }

    #[test]
    fn test_m6_check_redis_uses_lua_script_not_separate_commands() {
        // Structural test: check_redis must call Script::new / invoke_async,
        // NOT individual INCR + EXPIRE commands.
        let source = include_str!("rate_limit.rs");

        // Must use the Lua script approach
        assert!(
            source.contains("RATE_LIMIT_LUA"),
            "M-6: check_redis must reference RATE_LIMIT_LUA constant"
        );
        assert!(
            source.contains("invoke_async"),
            "M-6: check_redis must use invoke_async for atomic script execution"
        );
    }

    #[tokio::test]
    async fn test_m6_in_memory_backend_unaffected() {
        // Regression: the in-memory backend must still function correctly
        // after the Redis path was changed to use Lua scripting.
        let limiter = unwrap_ok!(RateLimiter::new(false, None, 5));

        // Verify basic rate limiting still works
        for i in 1..=5 {
            let result = unwrap_ok!(limiter.check("m6_regression_ip").await);
            assert!(result.allowed, "Request {} should be allowed", i);
            assert_eq!(result.remaining, 5 - i);
        }

        // 6th request should be blocked
        let result = unwrap_ok!(limiter.check("m6_regression_ip").await);
        assert!(!result.allowed, "6th request should be blocked");
        assert_eq!(result.remaining, 0);
        assert!(result.reset_in_secs <= 60);
    }

    #[tokio::test]
    async fn test_m6_disabled_backend_unaffected() {
        // Regression: the disabled backend must still work.
        let limiter = RateLimiter::disabled();
        let result = unwrap_ok!(limiter.check("any_ip").await);
        assert!(result.allowed);
        assert_eq!(result.remaining, u32::MAX);
    }
}
