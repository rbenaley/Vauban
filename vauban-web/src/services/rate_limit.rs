/// VAUBAN Web - Rate Limiting Service.
///
/// In-memory, single-process rate limiter. Vauban-web is a single sandboxed
/// process bastion, so a process-local counter is the correct scope (no
/// external cache server is involved, which keeps the limiter sandbox-safe:
/// it never opens a socket).
///
/// Callers pass both the key and the per-minute limit on every [`check`],
/// which lets a single limiter enforce different ceilings for different
/// concerns. Keys MUST be scoped by the caller to avoid collisions, e.g.
/// `login:{ip}`, `session:user:{uuid}`, `session:asset:{id}`,
/// `session:global`.
///
/// [`check`]: RateLimiter::check
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::debug;

use crate::error::AppResult;

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

/// In-memory rate limiter.
#[derive(Clone)]
pub enum RateLimiter {
    /// In-memory backend using DashMap.
    InMemory {
        store: Arc<DashMap<String, RateLimitEntry>>,
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
    /// Create an in-memory rate limiter.
    pub fn in_memory() -> Self {
        debug!("Rate limiter using in-memory backend");
        Self::InMemory {
            store: Arc::new(DashMap::new()),
        }
    }

    /// Create a disabled rate limiter.
    pub fn disabled() -> Self {
        Self::Disabled
    }

    /// Check if a request is allowed for the given key under `limit_per_minute`.
    ///
    /// The key must be pre-scoped by the caller (e.g. `login:{ip}`). A
    /// `limit_per_minute` of `0` is treated as "no limit" by callers that wish
    /// to disable a control; this method itself still counts, so callers pass
    /// the effective limit. The window is a fixed 60-second bucket per key.
    pub async fn check(&self, key: &str, limit_per_minute: u32) -> AppResult<RateLimitResult> {
        match self {
            Self::InMemory { store } => Ok(Self::check_in_memory(store, key, limit_per_minute)),
            Self::Disabled => Ok(RateLimitResult {
                allowed: true,
                remaining: u32::MAX,
                reset_in_secs: 0,
            }),
        }
    }

    /// Check rate limit using in-memory DashMap.
    fn check_in_memory(
        store: &DashMap<String, RateLimitEntry>,
        key: &str,
        limit: u32,
    ) -> RateLimitResult {
        let window_duration = Duration::from_secs(60);
        let now = Instant::now();

        let mut entry = store.entry(key.to_string()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Check if window has expired.
        let elapsed = now.duration_since(entry.window_start);
        if elapsed >= window_duration {
            entry.count = 1;
            entry.window_start = now;
        } else {
            entry.count += 1;
        }

        let count = entry.count;

        // Recalculate elapsed from the (possibly reset) window_start; use
        // saturating_sub as a safety net against timing edge cases.
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

        RateLimitResult {
            allowed,
            remaining,
            reset_in_secs,
        }
    }

    /// Clean up expired entries from in-memory store.
    ///
    /// Should be called periodically to prevent memory leaks.
    pub fn cleanup_expired(&self) {
        if let Self::InMemory { store, .. } = self {
            let now = Instant::now();
            let window_duration = Duration::from_secs(60);

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
        let limiter = RateLimiter::in_memory();
        for i in 1..=5 {
            let result = unwrap_ok!(limiter.check("test_ip", 5).await);
            assert!(result.allowed, "Request {} should be allowed", i);
            assert_eq!(result.remaining, 5 - i);
        }
    }

    #[tokio::test]
    async fn test_in_memory_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::in_memory();
        for _ in 0..3 {
            assert!(unwrap_ok!(limiter.check("test_ip", 3).await).allowed);
        }
        let result = unwrap_ok!(limiter.check("test_ip", 3).await);
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }

    #[tokio::test]
    async fn test_in_memory_rate_limiter_different_keys() {
        let limiter = RateLimiter::in_memory();
        let result1 = unwrap_ok!(limiter.check("ip1", 2).await);
        assert!(result1.allowed);
        assert_eq!(result1.remaining, 1);

        let result2 = unwrap_ok!(limiter.check("ip2", 2).await);
        assert!(result2.allowed);
        assert_eq!(result2.remaining, 1);

        let result3 = unwrap_ok!(limiter.check("ip1", 2).await);
        assert!(result3.allowed);
        assert_eq!(result3.remaining, 0);
    }

    #[tokio::test]
    async fn test_scopes_are_isolated() {
        // Different scope prefixes must NOT share a counter even with the same
        // suffix: a saturated login bucket must not block session creation.
        let limiter = RateLimiter::in_memory();

        // Saturate the login scope for ip "1.2.3.4".
        for _ in 0..2 {
            assert!(unwrap_ok!(limiter.check("login:1.2.3.4", 2).await).allowed);
        }
        assert!(!unwrap_ok!(limiter.check("login:1.2.3.4", 2).await).allowed);

        // The session scope for the same suffix is untouched.
        let session = unwrap_ok!(limiter.check("session:user:1.2.3.4", 2).await);
        assert!(
            session.allowed,
            "session scope must be independent of login"
        );
    }

    #[tokio::test]
    async fn test_same_key_different_limits() {
        // The limit is per-call: a stricter call on a key already at count N
        // can deny while a looser limit allows.
        let limiter = RateLimiter::in_memory();

        // count -> 1 with a high limit (allowed).
        assert!(unwrap_ok!(limiter.check("k", 100).await).allowed);
        // count -> 2, but a limit of 1 denies (2 > 1).
        assert!(!unwrap_ok!(limiter.check("k", 1).await).allowed);
    }

    #[tokio::test]
    async fn test_disabled_rate_limiter_always_allows() {
        let limiter = RateLimiter::disabled();
        for _ in 0..100 {
            let result = unwrap_ok!(limiter.check("any_ip", 1).await);
            assert!(result.allowed);
            assert_eq!(result.remaining, u32::MAX);
        }
    }

    #[tokio::test]
    async fn test_cleanup_expired_entries() {
        let limiter = RateLimiter::in_memory();
        if let RateLimiter::InMemory { store, .. } = &limiter {
            store.insert(
                "old_ip".to_string(),
                RateLimitEntry {
                    count: 5,
                    window_start: Instant::now() - Duration::from_secs(180),
                },
            );
            store.insert(
                "recent_ip".to_string(),
                RateLimitEntry {
                    count: 3,
                    window_start: Instant::now(),
                },
            );
            assert_eq!(store.len(), 2);

            limiter.cleanup_expired();

            assert_eq!(store.len(), 1);
            assert!(store.contains_key("recent_ip"));
            assert!(!store.contains_key("old_ip"));
        }
    }

    // ==================== Duration overflow prevention ====================

    #[tokio::test]
    async fn test_reset_in_secs_does_not_overflow_after_window_reset() {
        let limiter = RateLimiter::in_memory();
        if let RateLimiter::InMemory { store, .. } = &limiter {
            store.insert(
                "old_window_ip".to_string(),
                RateLimitEntry {
                    count: 5,
                    window_start: Instant::now() - Duration::from_secs(120),
                },
            );
            let result = unwrap_ok!(limiter.check("old_window_ip", 10).await);
            assert!(result.allowed);
            assert_eq!(result.remaining, 9);
            assert!(result.reset_in_secs <= 60);
        }
    }

    #[tokio::test]
    async fn test_reset_in_secs_with_very_old_entry() {
        let limiter = RateLimiter::in_memory();
        if let RateLimiter::InMemory { store, .. } = &limiter {
            store.insert(
                "very_old_ip".to_string(),
                RateLimitEntry {
                    count: 100,
                    window_start: Instant::now() - Duration::from_secs(3600),
                },
            );
            let result = unwrap_ok!(limiter.check("very_old_ip", 5).await);
            assert!(result.allowed);
            assert_eq!(result.remaining, 4);
        }
    }

    #[test]
    fn test_saturating_sub_behavior() {
        let small = Duration::from_secs(10);
        let large = Duration::from_secs(100);
        assert_eq!(small.saturating_sub(large), Duration::ZERO);
        assert_eq!(large.saturating_sub(small), Duration::from_secs(90));
    }

    #[tokio::test]
    async fn test_rate_limiter_reset_in_secs_is_reasonable() {
        let limiter = RateLimiter::in_memory();
        let result = unwrap_ok!(limiter.check("new_ip", 10).await);
        assert!(result.reset_in_secs <= 60);
    }

    #[tokio::test]
    async fn test_rate_limiter_multiple_requests_reset_time_decreases() {
        let limiter = RateLimiter::in_memory();
        let first_reset = unwrap_ok!(limiter.check("timing_ip", 100).await).reset_in_secs;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let second_reset = unwrap_ok!(limiter.check("timing_ip", 100).await).reset_in_secs;
        assert!(second_reset <= first_reset);
    }

    #[tokio::test]
    async fn test_in_memory_rate_limiter_still_functional() {
        let limiter = RateLimiter::in_memory();
        for i in 1..=3 {
            assert!(
                unwrap_ok!(limiter.check("regression_ip", 3).await).allowed,
                "Request {} should be allowed",
                i
            );
        }
        let result = unwrap_ok!(limiter.check("regression_ip", 3).await);
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }

    // ==================== No-network guarantee ====================

    #[test]
    fn test_source_opens_no_network_connection() {
        // SANDBOX PIN: the in-memory limiter must never open a socket. No
        // external cache crate import, no connection opener. Scan only the
        // production portion so this test's own assertion text (which names
        // the forbidden symbols) does not trip the check.
        let full = include_str!("rate_limit.rs");
        let source = full.split("#[cfg(test)]").next().unwrap_or(full);
        assert!(
            !source.contains("get_multiplexed_async_connection"),
            "rate_limit.rs must not open any network connection"
        );
        assert!(
            !source.contains("::Client::open"),
            "rate_limit.rs must not construct an external cache client"
        );
    }
}
