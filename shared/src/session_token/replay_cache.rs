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
        while let Some(front) = self.entries.front() {
            if now.duration_since(front.inserted_at) > self.ttl {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
