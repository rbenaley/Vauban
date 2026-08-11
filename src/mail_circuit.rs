//! Process-local circuit breaker for transactional SMTP (magic-link mail).
//!
//! When open, login requests share one "sign-in unavailable" outcome so SMTP
//! outages do not become an account-existence oracle.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::MailConfig;

#[derive(Debug)]
struct BreakerState {
    consecutive_failures: u32,
    /// When set and in the future, attempts are rejected (open).
    open_until: Option<Instant>,
}

/// In-process mail circuit breaker (`app_context`, keyed for the whole process).
#[derive(Debug)]
pub struct MailCircuitBreaker {
    inner: Mutex<BreakerState>,
    failure_threshold: u32,
    open_for: Duration,
}

impl MailCircuitBreaker {
    pub fn new(cfg: &MailConfig) -> Self {
        Self {
            inner: Mutex::new(BreakerState {
                consecutive_failures: 0,
                open_until: None,
            }),
            failure_threshold: cfg.circuit_failure_threshold.max(1),
            open_for: Duration::from_secs(cfg.circuit_open_secs.max(1)),
        }
    }

    /// Whether a login / send attempt may proceed.
    ///
    /// Open → `false` until `open_secs` elapses (half-open: traffic allowed again;
    /// the next SMTP failure re-opens, success closes).
    pub fn allow_attempt(&self) -> bool {
        !self.is_open()
    }

    /// Record a successful SMTP delivery (closes the breaker).
    pub fn record_success(&self) {
        let mut state = self.inner.lock().expect("mail circuit mutex");
        state.consecutive_failures = 0;
        state.open_until = None;
    }

    /// Record an SMTP send failure; may open the breaker.
    pub fn record_failure(&self) {
        let mut state = self.inner.lock().expect("mail circuit mutex");
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.failure_threshold {
            let until = Instant::now() + self.open_for;
            state.open_until = Some(until);
            tracing::error!(
                consecutive_failures = state.consecutive_failures,
                open_secs = self.open_for.as_secs(),
                "mail circuit opened after SMTP failures; sign-in links unavailable until recovery"
            );
        }
    }

    /// Test / ops helper: force the open state immediately.
    pub fn force_open(&self) {
        let mut state = self.inner.lock().expect("mail circuit mutex");
        state.consecutive_failures = self.failure_threshold;
        state.open_until = Some(Instant::now() + self.open_for);
    }

    /// Whether the breaker is currently rejecting attempts.
    pub fn is_open(&self) -> bool {
        let state = self.inner.lock().expect("mail circuit mutex");
        match state.open_until {
            Some(until) => Instant::now() < until,
            None => false,
        }
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.inner
            .lock()
            .expect("mail circuit mutex")
            .consecutive_failures
    }

    /// Pure helper for unit / proptest: whether `failures` trips open at `threshold`.
    pub fn should_open(failures: u32, threshold: u32) -> bool {
        failures >= threshold.max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SmtpEncryption;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn breaker(threshold: u32, open_secs: u64) -> MailCircuitBreaker {
        MailCircuitBreaker::new(&MailConfig {
            smtp_host: "localhost".to_owned(),
            smtp_port: 1025,
            smtp_encryption: SmtpEncryption::Plaintext,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_accept_invalid_certs: false,
            circuit_failure_threshold: threshold,
            circuit_open_secs: open_secs,
        })
    }

    #[test]
    fn allow_when_closed() {
        let b = breaker(3, 60);
        assert!(b.allow_attempt());
        assert!(!b.is_open());
    }

    #[test]
    fn opens_after_threshold_failures() {
        let b = breaker(3, 60);
        b.record_failure();
        b.record_failure();
        assert!(b.allow_attempt());
        b.record_failure();
        assert!(b.is_open());
        assert!(!b.allow_attempt());
    }

    #[test]
    fn success_resets_failures() {
        let b = breaker(3, 60);
        b.record_failure();
        b.record_failure();
        b.record_success();
        assert_eq!(b.consecutive_failures(), 0);
        assert!(b.allow_attempt());
    }

    #[test]
    fn force_open_rejects_until_success() {
        let b = breaker(3, 60);
        b.force_open();
        assert!(!b.allow_attempt());
        b.record_success();
        assert!(b.allow_attempt());
        assert!(!b.is_open());
    }

    #[test]
    fn half_open_after_window_allows_again() {
        let b = breaker(1, 1);
        b.record_failure();
        assert!(!b.allow_attempt());
        thread::sleep(Duration::from_millis(1_100));
        assert!(
            b.allow_attempt(),
            "after open window, traffic is allowed again"
        );
        b.record_failure();
        assert!(b.is_open(), "failure while half-open re-opens");
    }

    #[test]
    fn battle_parallel_record_failure_opens_once() {
        let b = Arc::new(breaker(5, 60));
        let n = 8usize;
        let barrier = Arc::new(Barrier::new(n));
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let b = b.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                b.record_failure();
            }));
        }
        for h in handles {
            h.join().expect("join");
        }
        assert!(b.is_open() || b.consecutive_failures() >= 5);
        assert!(MailCircuitBreaker::should_open(5, 5));
        assert!(!MailCircuitBreaker::should_open(4, 5));
    }
}
