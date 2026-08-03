//! Login anti-enumeration: per-email rate limit for magic-link requests.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::LoginConfig;

#[derive(Debug, Clone)]
struct AttemptWindow {
    failures: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

/// In-process per-email login rate limiter (keyed by normalized email).
#[derive(Debug)]
pub struct LoginRateLimiter {
    inner: Mutex<HashMap<String, AttemptWindow>>,
    max_attempts: u32,
    window: Duration,
    lockout: Duration,
}

impl LoginRateLimiter {
    pub fn new(cfg: &LoginConfig) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_attempts: cfg.max_attempts.max(1),
            window: Duration::from_secs(cfg.window_secs.max(1)),
            lockout: Duration::from_secs(cfg.lockout_secs.max(1)),
        }
    }

    /// Whether a magic-link request for this email is currently allowed.
    pub fn allow(&self, email: &str) -> bool {
        let mut map = self.inner.lock().expect("login limiter mutex");
        let now = Instant::now();
        let entry = map.entry(email.to_owned()).or_insert(AttemptWindow {
            failures: 0,
            window_start: now,
            locked_until: None,
        });
        if let Some(until) = entry.locked_until {
            if now < until {
                return false;
            }
            entry.locked_until = None;
            entry.failures = 0;
            entry.window_start = now;
        }
        if now.duration_since(entry.window_start) > self.window {
            entry.failures = 0;
            entry.window_start = now;
        }
        Self::decide(entry.failures, self.max_attempts, false)
    }

    /// Record a failed / unknown-email request.
    pub fn record_failure(&self, email: &str) {
        let mut map = self.inner.lock().expect("login limiter mutex");
        let now = Instant::now();
        let entry = map.entry(email.to_owned()).or_insert(AttemptWindow {
            failures: 0,
            window_start: now,
            locked_until: None,
        });
        if let Some(until) = entry.locked_until
            && now < until
        {
            return;
        }
        if now.duration_since(entry.window_start) > self.window {
            entry.failures = 0;
            entry.window_start = now;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= self.max_attempts {
            entry.locked_until = Some(now + self.lockout);
        }
    }

    /// Clear the window after a successful magic-link issue.
    pub fn clear(&self, email: &str) {
        let mut map = self.inner.lock().expect("login limiter mutex");
        map.remove(email);
    }

    pub fn failure_count(&self, email: &str) -> u32 {
        let map = self.inner.lock().expect("login limiter mutex");
        map.get(email).map(|e| e.failures).unwrap_or(0)
    }

    /// Pure helper for tests / proptest.
    pub fn decide(failures: u32, max: u32, locked: bool) -> bool {
        !locked && failures < max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(max: u32) -> LoginRateLimiter {
        LoginRateLimiter::new(&LoginConfig {
            max_attempts: max,
            window_secs: 300,
            lockout_secs: 900,
        })
    }

    #[test]
    fn auth_tenant_rate_limiter_allows_under_cap() {
        let lim = limiter(3);
        assert!(lim.allow("a@example.com"));
        lim.record_failure("a@example.com");
        lim.record_failure("a@example.com");
        assert!(lim.allow("a@example.com"));
    }

    #[test]
    fn auth_tenant_rate_limiter_locks_at_max() {
        let lim = limiter(2);
        lim.record_failure("b@example.com");
        lim.record_failure("b@example.com");
        assert!(!lim.allow("b@example.com"));
    }

    #[test]
    fn auth_tenant_rate_limiter_clear_resets() {
        let lim = limiter(1);
        lim.record_failure("c@example.com");
        assert!(!lim.allow("c@example.com"));
        lim.clear("c@example.com");
        assert!(lim.allow("c@example.com"));
    }

    #[test]
    fn auth_tenant_decide_helper() {
        assert!(LoginRateLimiter::decide(0, 5, false));
        assert!(!LoginRateLimiter::decide(5, 5, false));
        assert!(!LoginRateLimiter::decide(0, 5, true));
    }
}
