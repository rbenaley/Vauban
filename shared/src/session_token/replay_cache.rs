//! Bounded, TTL-aware anti-replay cache for cryptographic session
//! tokens.
//!
//! Holds the `(session_id, nonce)` pair of every token successfully
//! verified by a session-token verifier (supervisor or proxy). A
//! second presentation of the same pair within the token TTL is
//! rejected.
//!
//! Re-used identically by `vauban-supervisor` and by every protocol
//! proxy via [`super::proxy_gate`]. Sharing the implementation
//! guarantees that the anti-replay window is the same at every
//! verification point and removes the per-proxy copy that previously
//! existed in `vauban-proxy-ssh::session_token_gate` and
//! `vauban-proxy-rdp::session_token_gate`.
//!
//! Design choices:
//! - Bounded LRU: the cache cannot exceed [`MAX_ENTRIES`] entries; the
//!   oldest entry is evicted when full. The bound prevents a confused
//!   or compromised caller from forcing unbounded memory growth.
//! - Time-based GC: entries expire [`super::TOKEN_TTL_SECONDS`] after
//!   insertion, so a replay attempted after the token would have
//!   expired anyway is rejected by the verifier itself, not the
//!   cache. We still keep the entry until eviction so a compressed
//!   clock skew does not let a replayer slip through.
//! - Per-process: every verifier owns its own cache. Cross-process
//!   replay is already prevented by the verifier role splitting
//!   (different `Verifier` variants check different fields), so a
//!   shared cache would add coupling without security benefit.

use super::{NONCE_LENGTH, TOKEN_TTL_SECONDS};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Maximum number of entries kept in the replay cache.
///
/// Sized to comfortably hold every concurrent session-open in flight
/// over the TTL window, even under load: 4096 sessions / 30 s is
/// ~136 sessions/s, well above realistic bastion throughput.
pub const MAX_ENTRIES: usize = 4096;

#[derive(Debug, Clone)]
struct Entry {
    session_id: String,
    nonce: [u8; NONCE_LENGTH],
    inserted_at: Instant,
}

/// Bounded, TTL-aware replay cache.
#[derive(Debug)]
pub struct ReplayCache {
    entries: VecDeque<Entry>,
    ttl: Duration,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_ENTRIES),
            ttl: Duration::from_secs(TOKEN_TTL_SECONDS),
        }
    }

    /// Test-only constructor with a custom TTL (avoids sleeping for
    /// [`TOKEN_TTL_SECONDS`] in eviction tests).
    #[cfg(test)]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_ENTRIES),
            ttl,
        }
    }

    /// Try to record `(session_id, nonce)`. Returns `false` if the same
    /// pair has been recorded within the TTL window (replay detected).
    pub fn record(&mut self, session_id: &str, nonce: &[u8; NONCE_LENGTH]) -> bool {
        self.evict_expired();
        if self
            .entries
            .iter()
            .any(|e| e.session_id == session_id && &e.nonce == nonce)
        {
            return false;
        }
        if self.entries.len() == MAX_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(Entry {
            session_id: session_id.to_string(),
            nonce: *nonce,
            inserted_at: Instant::now(),
        });
        true
    }

    fn evict_expired(&mut self) {
        let now = Instant::now();
        let ttl = self.ttl;
        while self
            .entries
            .pop_front_if(|e| now.duration_since(e.inserted_at) > ttl)
            .is_some()
        {}
    }

    /// Backdate every entry so the next [`Self::record`] / eviction pass
    /// treats them as older than `age` (test harness only).
    #[cfg(test)]
    pub fn backdate_all_for_test(&mut self, age: Duration) {
        let now = Instant::now();
        for e in &mut self.entries {
            e.inserted_at = now.checked_sub(age).unwrap_or(e.inserted_at);
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    fn nonce(b: u8) -> [u8; NONCE_LENGTH] {
        [b; NONCE_LENGTH]
    }

    #[test]
    fn first_record_succeeds() {
        let mut cache = ReplayCache::new();
        assert!(cache.record("sess-1", &nonce(1)));
    }

    #[test]
    fn replay_same_pair_rejected() {
        let mut cache = ReplayCache::new();
        assert!(cache.record("sess-1", &nonce(1)));
        assert!(!cache.record("sess-1", &nonce(1)));
    }

    #[test]
    fn different_nonce_same_session_accepted() {
        let mut cache = ReplayCache::new();
        assert!(cache.record("sess-1", &nonce(1)));
        assert!(cache.record("sess-1", &nonce(2)));
    }

    #[test]
    fn different_session_same_nonce_accepted() {
        let mut cache = ReplayCache::new();
        assert!(cache.record("sess-1", &nonce(1)));
        assert!(cache.record("sess-2", &nonce(1)));
    }

    #[test]
    fn cache_respects_max_entries() {
        let mut cache = ReplayCache::new();
        for i in 0..(MAX_ENTRIES + 50) {
            assert!(cache.record(&format!("s{i}"), &nonce((i % 256) as u8)));
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
    }

    #[test]
    fn expired_entries_evicted_before_replay_check() {
        let mut cache = ReplayCache::with_ttl(Duration::from_secs(1));
        assert!(cache.record("sess-1", &nonce(1)));
        assert!(!cache.record("sess-1", &nonce(1)));
        cache.backdate_all_for_test(Duration::from_secs(2));
        // Expired: same pair must be accepted again.
        assert!(cache.record("sess-1", &nonce(1)));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn evict_expired_uses_pop_front_if() {
        let src = include_str!("replay_cache.rs");
        let fn_start = src
            .find("fn evict_expired")
            .expect("evict_expired must exist");
        let body = &src[fn_start..];
        let fn_end = body
            .find("\n    #[cfg(test)]")
            .unwrap_or(body.len().min(400));
        let body = &body[..fn_end];
        assert!(
            body.contains("pop_front_if"),
            "evict_expired must use VecDeque::pop_front_if"
        );
        assert!(
            !body.contains("while let Some(front) = self.entries.front()"),
            "evict_expired must not use the legacy front()/pop_front loop"
        );
    }

    /// Battle: concurrent record under a shared Mutex -- no panic, bound
    /// honored, same-pair replays rejected while within TTL.
    #[test]
    fn battle_concurrent_record_under_mutex() {
        let cache = Arc::new(Mutex::new(ReplayCache::new()));
        let n = 8usize;
        let barrier = Arc::new(Barrier::new(n));
        let mut handles = Vec::with_capacity(n);
        for t in 0..n {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for i in 0..64 {
                    let sid = format!("s{t}-{i}");
                    let n = nonce(((t * 64 + i) % 256) as u8);
                    let mut guard = cache.lock().expect("lock");
                    assert!(guard.record(&sid, &n));
                    assert!(!guard.record(&sid, &n), "replay must be rejected");
                    assert!(guard.len() <= MAX_ENTRIES);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        let guard = cache.lock().expect("lock");
        assert!(guard.len() <= MAX_ENTRIES);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// After backdating past TTL, previously recorded pairs can be
        /// recorded again.
        #[test]
        fn expired_entries_allow_rerecord(n in 1usize..32) {
            let mut cache = ReplayCache::with_ttl(Duration::from_millis(50));
            let mut pairs = Vec::with_capacity(n);
            for i in 0..n {
                let sid = format!("sess-{i}");
                let nonce = [(i % 256) as u8; NONCE_LENGTH];
                prop_assert!(cache.record(&sid, &nonce));
                pairs.push((sid, nonce));
            }
            prop_assert_eq!(cache.len(), n);
            cache.backdate_all_for_test(Duration::from_millis(100));
            for (sid, nonce) in &pairs {
                prop_assert!(
                    cache.record(sid, nonce),
                    "expired pair must be accepted again: {sid}"
                );
            }
            prop_assert_eq!(cache.len(), n);
        }
    }
}
