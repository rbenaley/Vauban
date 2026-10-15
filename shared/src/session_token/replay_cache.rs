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
//! - Per-token retention: an entry lives until its own token's
//!   `expires_at` (unix seconds). A 1 h MCP token stays recorded for
//!   the hour; a 30 s TCP token for 30 s. Past `expires_at` the
//!   verifier rejects the token itself, so dropping the entry opens no
//!   replay window.
//! - Bounded: the cache cannot exceed [`MAX_ENTRIES`] entries. When it
//!   is full after expired entries are dropped, the entry whose token
//!   expires first is evicted, which keeps the shortest possible
//!   replay window instead of discarding a long-lived token's entry.
//! - Caller clock: `now` is the same unix time the verifier used for
//!   the expiry check, so the cache and the verifier agree on what is
//!   expired.
//! - Per-process: every verifier owns its own cache. Cross-process
//!   replay is already prevented by the verifier role splitting
//!   (different `Verifier` variants check different fields), so a
//!   shared cache would add coupling without security benefit.

use super::NONCE_LENGTH;

/// Maximum number of entries kept in the replay cache.
pub const MAX_ENTRIES: usize = 4096;

#[derive(Debug, Clone)]
struct Entry {
    session_id: String,
    nonce: [u8; NONCE_LENGTH],
    expires_at: u64,
}

/// Bounded replay cache; each entry expires with its token.
#[derive(Debug, Default)]
pub struct ReplayCache {
    entries: Vec<Entry>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to record `(session_id, nonce)` for a token valid until
    /// `expires_at`. Returns `false` if the same pair is still recorded
    /// (replay detected).
    pub fn record(
        &mut self,
        session_id: &str,
        nonce: &[u8; NONCE_LENGTH],
        expires_at: u64,
        now: u64,
    ) -> bool {
        self.entries.retain(|e| e.expires_at >= now);
        if self
            .entries
            .iter()
            .any(|e| e.session_id == session_id && &e.nonce == nonce)
        {
            return false;
        }
        if self.entries.len() >= MAX_ENTRIES
            && let Some(i) = (0..self.entries.len()).min_by_key(|&i| self.entries[i].expires_at)
        {
            self.entries.swap_remove(i);
        }
        self.entries.push(Entry {
            session_id: session_id.to_string(),
            nonce: *nonce,
            expires_at,
        });
        true
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
    use crate::session_token::{TOKEN_TTL_SECONDS, TOKEN_TTL_SECONDS_MCP};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    const T0: u64 = 1_700_000_000;

    fn nonce(b: u8) -> [u8; NONCE_LENGTH] {
        [b; NONCE_LENGTH]
    }

    #[test]
    fn first_record_succeeds() {
        let mut cache = ReplayCache::new();
        assert!(cache.is_empty());
        assert!(cache.record("sess-1", &nonce(1), T0 + 30, T0));
    }

    #[test]
    fn replay_same_pair_rejected() {
        let mut cache = ReplayCache::new();
        assert!(cache.record("sess-1", &nonce(1), T0 + 30, T0));
        assert!(!cache.record("sess-1", &nonce(1), T0 + 30, T0));
    }

    #[test]
    fn different_nonce_same_session_accepted() {
        let mut cache = ReplayCache::new();
        assert!(cache.record("sess-1", &nonce(1), T0 + 30, T0));
        assert!(cache.record("sess-1", &nonce(2), T0 + 30, T0));
    }

    #[test]
    fn different_session_same_nonce_accepted() {
        let mut cache = ReplayCache::new();
        assert!(cache.record("sess-1", &nonce(1), T0 + 30, T0));
        assert!(cache.record("sess-2", &nonce(1), T0 + 30, T0));
    }

    /// A 1 h MCP token replayed after 31 s is still refused.
    #[test]
    fn mcp_token_replay_after_31s_rejected() {
        let mut cache = ReplayCache::new();
        let exp = T0 + TOKEN_TTL_SECONDS_MCP;
        assert!(cache.record("mcp-1", &nonce(7), exp, T0));
        assert!(!cache.record("mcp-1", &nonce(7), exp, T0 + TOKEN_TTL_SECONDS + 1));
        assert!(
            !cache.record("mcp-1", &nonce(7), exp, exp),
            "valid at expires_at"
        );
        assert!(
            cache.record("mcp-1", &nonce(7), exp, exp + 1),
            "past expires_at the verifier refuses the token; the entry may go"
        );
    }

    #[test]
    fn short_token_expires_without_dropping_long_one() {
        let mut cache = ReplayCache::new();
        assert!(cache.record("tcp", &nonce(1), T0 + TOKEN_TTL_SECONDS, T0));
        assert!(cache.record("mcp", &nonce(2), T0 + TOKEN_TTL_SECONDS_MCP, T0));
        let later = T0 + TOKEN_TTL_SECONDS + 1;
        assert!(cache.record("other", &nonce(3), later + 30, later));
        assert_eq!(cache.len(), 2, "only the 30 s entry expired");
        assert!(!cache.record("mcp", &nonce(2), T0 + TOKEN_TTL_SECONDS_MCP, later));
    }

    /// When full, the entry expiring first is evicted, never a longer one.
    #[test]
    fn full_cache_evicts_soonest_expiry() {
        let mut cache = ReplayCache::new();
        assert!(cache.record("long", &nonce(0), T0 + 3600, T0));
        for i in 1..MAX_ENTRIES {
            assert!(cache.record(
                &format!("s{i}"),
                &nonce((i % 256) as u8),
                T0 + 60 + i as u64,
                T0
            ));
        }
        assert!(cache.record("short", &nonce(1), T0 + 40, T0));
        assert_eq!(cache.len(), MAX_ENTRIES);
        assert!(cache.record("next", &nonce(2), T0 + 50, T0));
        assert_eq!(cache.len(), MAX_ENTRIES);
        assert!(
            !cache.record("long", &nonce(0), T0 + 3600, T0),
            "long entry kept"
        );
        assert!(
            cache.record("short", &nonce(1), T0 + 40, T0),
            "soonest entry evicted"
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
                    assert!(guard.record(&sid, &n, T0 + 30, T0));
                    assert!(
                        !guard.record(&sid, &n, T0 + 30, T0),
                        "replay must be rejected"
                    );
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

        /// Within its own lifetime a pair is always refused; after it,
        /// it can be recorded again.
        #[test]
        fn pair_refused_until_its_own_expiry(n in 1usize..32, ttl in 1u64..7200, dt in 0u64..7200) {
            let t0 = 1_700_000_000u64;
            let mut cache = ReplayCache::new();
            for i in 0..n {
                let sid = format!("sess-{i}");
                prop_assert!(cache.record(&sid, &[(i % 256) as u8; NONCE_LENGTH], t0 + ttl, t0));
            }
            let now = t0 + dt;
            for i in 0..n {
                let sid = format!("sess-{i}");
                let fresh = cache.record(&sid, &[(i % 256) as u8; NONCE_LENGTH], now + ttl, now);
                prop_assert_eq!(fresh, dt > ttl, "dt={} ttl={}", dt, ttl);
            }
        }
    }
}
