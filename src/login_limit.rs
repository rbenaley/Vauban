//! Login anti-enumeration: constant-time-ish verify + per-email rate limit.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::LoginConfig;
use crate::db::verify_password;

/// Precomputed Argon2 hash used when the email is unknown so verify always runs.
fn dummy_password_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        // Fixed secret — never a real user password. Computed once per process.
        crate::db::hash_password("vcp-login-dummy-never-match-7f3a9c2e")
            .expect("dummy password hash")
    })
}

/// Always runs Argon2 verify (real hash or dummy) to reduce timing oracles.
pub fn verify_login_password(password: &str, stored_hash: Option<&str>) -> bool {
    let hash = stored_hash.unwrap_or_else(|| dummy_password_hash());
    verify_password(password, hash) && stored_hash.is_some()
}

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

    /// Pure decision helper for unit / proptest tests.
    pub fn decide(failures: u32, max_attempts: u32, locked: bool) -> bool {
        !locked && failures < max_attempts
    }

    /// Returns `true` when a login attempt may proceed.
    pub fn allow(&self, email: &str) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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

    pub fn record_failure(&self, email: &str) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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

    pub fn clear(&self, email: &str) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(email);
    }

    #[cfg(test)]
    pub fn failure_count(&self, email: &str) -> u32 {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.get(email).map(|e| e.failures).unwrap_or(0)
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
    fn auth_tenant_rate_limiter_allows_under_max() {
        let lim = limiter(3);
        assert!(lim.allow("a@example.com"));
        lim.record_failure("a@example.com");
        lim.record_failure("a@example.com");
        assert!(lim.allow("a@example.com"));
        assert_eq!(lim.failure_count("a@example.com"), 2);
    }

    #[test]
    fn auth_tenant_rate_limiter_locks_at_max() {
        let lim = limiter(2);
        assert!(lim.allow("b@example.com"));
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
    fn auth_tenant_verify_login_unknown_email_runs_dummy() {
        assert!(!verify_login_password("anything", None));
    }

    #[test]
    fn auth_tenant_verify_login_wrong_password() {
        let hash = crate::db::hash_password("correct").unwrap();
        assert!(!verify_login_password("wrong", Some(&hash)));
        assert!(verify_login_password("correct", Some(&hash)));
    }

    #[test]
    fn auth_tenant_decide_helper() {
        assert!(LoginRateLimiter::decide(0, 5, false));
        assert!(!LoginRateLimiter::decide(5, 5, false));
        assert!(!LoginRateLimiter::decide(0, 5, true));
    }
}
