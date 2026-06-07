//! Activity throttle for refreshing `auth_sessions.last_activity` from a
//! long-lived WebSocket.
//!
//! During an SSH/RDP session every keystroke / mouse event arrives over
//! the WebSocket, which would hammer the database if each one triggered a
//! `last_activity` update. [`ActivityThrottle`] collapses a burst of input
//! into at most one update per `min_interval`: the first event after the
//! window fires, the rest are suppressed until the window elapses again.
//!
//! It is deliberately a pure, clock-injected state machine (no async, no
//! DB) so it can be unit-tested deterministically with a fake `Instant`.

use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::AppState;

/// Refresh `auth_sessions.last_activity` for `session_uuid` to "now".
///
/// Public, DB-touching counterpart used by the SSH/RDP WebSocket handlers
/// to keep a login session alive while the user is active over a
/// long-lived socket (the front-end `/htmx/empty` heartbeat handles the
/// complementary cookie renewal). Callers MUST gate this behind an
/// [`ActivityThrottle`] so a burst of input does not hammer the database.
pub async fn touch_login_session(state: &AppState, session_uuid: Uuid) {
    crate::middleware::auth::update_last_activity(state, session_uuid).await;
}

/// Collapses high-frequency activity into at most one "fire" per
/// `min_interval`.
#[derive(Debug)]
pub struct ActivityThrottle {
    last_fired: Option<Instant>,
    min_interval: Duration,
}

impl ActivityThrottle {
    /// Create a throttle that fires at most once per `min_interval`.
    pub fn new(min_interval: Duration) -> Self {
        Self {
            last_fired: None,
            min_interval,
        }
    }

    /// Returns `true` if a refresh should happen at `now`, recording the
    /// firing instant. The first call always fires; subsequent calls
    /// within `min_interval` of the last firing are suppressed.
    pub fn should_fire(&mut self, now: Instant) -> bool {
        let due = match self.last_fired {
            None => true,
            Some(prev) => now.duration_since(prev) >= self.min_interval,
        };
        if due {
            self.last_fired = Some(now);
        }
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_on_first_call() {
        let mut t = ActivityThrottle::new(Duration::from_secs(60));
        assert!(t.should_fire(Instant::now()));
    }

    #[test]
    fn suppresses_within_interval() {
        let mut t = ActivityThrottle::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(t.should_fire(t0));
        // Same instant and a point within the window are both suppressed.
        assert!(!t.should_fire(t0));
        assert!(!t.should_fire(t0 + Duration::from_secs(59)));
    }

    #[test]
    fn refires_after_interval() {
        let mut t = ActivityThrottle::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(t.should_fire(t0));
        assert!(!t.should_fire(t0 + Duration::from_secs(30)));
        // Exactly at the boundary it fires again...
        assert!(t.should_fire(t0 + Duration::from_secs(60)));
        // ...and the window now restarts from that firing.
        assert!(!t.should_fire(t0 + Duration::from_secs(90)));
        assert!(t.should_fire(t0 + Duration::from_secs(120)));
    }

    #[test]
    fn zero_interval_always_fires() {
        let mut t = ActivityThrottle::new(Duration::from_secs(0));
        let t0 = Instant::now();
        assert!(t.should_fire(t0));
        assert!(t.should_fire(t0));
    }
}
