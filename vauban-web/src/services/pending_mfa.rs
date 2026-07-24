//! In-memory store for pending (candidate) MFA secrets.
//!
//! VAU-008 (ephemeral variant): during enrolment the candidate TOTP secret
//! MUST NOT be persisted to the database before the user confirms a valid
//! code, and it MUST be isolated per login session so that two browsers (or a
//! third party who created the account) never share the same candidate.
//!
//! The candidate therefore lives here, in a process-local [`DashMap`] keyed by
//! `(user_uuid, session_uuid)` -- the latter being the JWT `jti`
//! (`auth_sessions.uuid`). It is removed the moment enrolment succeeds, and it
//! expires after [`PendingMfaStore::TTL`].
//!
//! Trade-off (documented): the map is local to the process, so an enrolment in
//! progress is bound to the instance that generated it. A single-instance
//! bastion is unaffected; a multi-instance (HA) deployment must pin the
//! enrolment session to one instance (sticky) or migrate this store to a
//! shared backend.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// A candidate secret awaiting confirmation, plus the instant it was created
/// (for TTL expiry).
#[derive(Clone)]
struct PendingEntry {
    /// The candidate secret. Encrypted envelope (`vN:...`) when a vault is
    /// configured, plaintext Base32 in dev.
    secret: String,
    created_at: Instant,
}

/// Process-local, per-session store of candidate MFA secrets.
///
/// Cheap to clone (`Arc` inside); a single instance is shared via [`AppState`].
#[derive(Clone, Default)]
pub struct PendingMfaStore {
    inner: Arc<DashMap<String, PendingEntry>>,
}

impl PendingMfaStore {
    /// Lifetime of a candidate secret. After this, a confirmation is refused
    /// and the entry is evicted.
    pub const TTL: Duration = Duration::from_secs(15 * 60);

    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    /// Cache key binding the candidate to BOTH the user and the login session.
    fn key(user_uuid: &str, session_uuid: &str) -> String {
        format!("{user_uuid}:{session_uuid}")
    }

    /// Store a freshly generated candidate, overwriting any previous one for
    /// this `(user, session)`. Overwriting is the "regenerate as many times as
    /// necessary" behaviour: each init produces a brand new secret.
    pub fn put(&self, user_uuid: &str, session_uuid: &str, secret: String) {
        self.inner.insert(
            Self::key(user_uuid, session_uuid),
            PendingEntry {
                secret,
                created_at: Instant::now(),
            },
        );
    }

    /// Fetch the candidate for this `(user, session)` if present and not older
    /// than [`Self::TTL`]. A stale entry is evicted and treated as absent.
    pub fn get(&self, user_uuid: &str, session_uuid: &str) -> Option<String> {
        let key = Self::key(user_uuid, session_uuid);
        // The DashMap read guard from `get` is dropped at the end of this `if`
        // (let-chain temporaries), so the subsequent `remove` cannot deadlock.
        if let Some(entry) = self.inner.get(&key)
            && entry.created_at.elapsed() <= Self::TTL
        {
            return Some(entry.secret.clone());
        }
        // Either absent or stale: ensure no stale entry lingers.
        self.inner.remove(&key);
        None
    }

    /// Remove the candidate for this `(user, session)` (called on successful
    /// enrolment).
    pub fn evict(&self, user_uuid: &str, session_uuid: &str) {
        self.inner.remove(&Self::key(user_uuid, session_uuid));
    }

    /// Drop every entry older than [`Self::TTL`]. Called periodically to bound
    /// memory from abandoned enrolments.
    ///
    /// DashMap has no `HashMap::extract_if`; we collect stale keys then
    /// remove (same semantics as extract_if on a plain HashMap).
    pub fn sweep(&self) {
        let stale_keys: Vec<String> = self
            .inner
            .iter()
            .filter_map(|entry| {
                if entry.created_at.elapsed() > Self::TTL {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for key in stale_keys {
            self.inner.remove(&key);
        }
    }

    /// Number of live entries (test/diagnostic helper).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the store is empty (test/diagnostic helper).
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_returns_the_secret() {
        let store = PendingMfaStore::new();
        store.put("user-a", "sess-1", "SECRET_A".to_string());
        assert_eq!(store.get("user-a", "sess-1").as_deref(), Some("SECRET_A"));
    }

    #[test]
    fn entries_are_isolated_per_session() {
        let store = PendingMfaStore::new();
        store.put("user-a", "sess-1", "SECRET_1".to_string());
        store.put("user-a", "sess-2", "SECRET_2".to_string());
        // Same user, two sessions -> two independent candidates (INV-2).
        assert_eq!(store.get("user-a", "sess-1").as_deref(), Some("SECRET_1"));
        assert_eq!(store.get("user-a", "sess-2").as_deref(), Some("SECRET_2"));
    }

    #[test]
    fn entries_are_isolated_per_user() {
        let store = PendingMfaStore::new();
        store.put("user-a", "sess-1", "SECRET_A".to_string());
        store.put("user-b", "sess-1", "SECRET_B".to_string());
        assert_eq!(store.get("user-a", "sess-1").as_deref(), Some("SECRET_A"));
        assert_eq!(store.get("user-b", "sess-1").as_deref(), Some("SECRET_B"));
    }

    #[test]
    fn put_overwrites_and_regenerates() {
        let store = PendingMfaStore::new();
        store.put("user-a", "sess-1", "OLD".to_string());
        store.put("user-a", "sess-1", "NEW".to_string());
        assert_eq!(store.get("user-a", "sess-1").as_deref(), Some("NEW"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn evict_removes_the_entry() {
        let store = PendingMfaStore::new();
        store.put("user-a", "sess-1", "SECRET".to_string());
        store.evict("user-a", "sess-1");
        assert!(store.get("user-a", "sess-1").is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn get_evicts_a_stale_entry() {
        let store = PendingMfaStore::new();
        // Insert an entry whose created_at is already beyond the TTL.
        store.inner.insert(
            PendingMfaStore::key("user-a", "sess-1"),
            PendingEntry {
                secret: "STALE".to_string(),
                created_at: Instant::now() - (PendingMfaStore::TTL + Duration::from_secs(1)),
            },
        );
        assert!(store.get("user-a", "sess-1").is_none());
        assert_eq!(store.len(), 0, "stale entry must be evicted on read");
    }

    #[test]
    fn sweep_drops_only_stale_entries() {
        let store = PendingMfaStore::new();
        store.put("fresh", "s", "FRESH".to_string());
        store.inner.insert(
            PendingMfaStore::key("stale", "s"),
            PendingEntry {
                secret: "STALE".to_string(),
                created_at: Instant::now() - (PendingMfaStore::TTL + Duration::from_secs(1)),
            },
        );
        store.sweep();
        assert_eq!(store.get("fresh", "s").as_deref(), Some("FRESH"));
        assert!(store.get("stale", "s").is_none());
    }

    #[test]
    fn sweep_uses_collect_then_remove_not_retain() {
        let full = include_str!("pending_mfa.rs");
        let prod = full.split("#[cfg(test)]").next().unwrap_or(full);
        let fn_start = prod.find("pub fn sweep").expect("sweep must exist");
        let body = &prod[fn_start..];
        let fn_end = body
            .find("\n    /// Number of live")
            .unwrap_or(body.len().min(600));
        let body = &body[..fn_end];
        assert!(
            body.contains("stale_keys") && body.contains("self.inner.remove"),
            "sweep must collect stale keys then remove (DashMap extract_if equivalent)"
        );
        assert!(
            !body.contains(".retain("),
            "sweep must not use DashMap::retain"
        );
    }

    /// Proptest-style: mixed fresh/stale corpus survives sweep correctly.
    #[test]
    fn sweep_proptest_mixed_fresh_and_stale() {
        let store = PendingMfaStore::new();
        for i in 0..16 {
            let user = format!("u{i}");
            if i % 3 == 0 {
                store.inner.insert(
                    PendingMfaStore::key(&user, "s"),
                    PendingEntry {
                        secret: format!("STALE{i}"),
                        created_at: Instant::now()
                            - (PendingMfaStore::TTL + Duration::from_secs(1 + i as u64)),
                    },
                );
            } else {
                store.put(&user, "s", format!("FRESH{i}"));
            }
        }
        store.sweep();
        for i in 0..16 {
            let user = format!("u{i}");
            if i % 3 == 0 {
                assert!(store.get(&user, "s").is_none(), "stale u{i}");
            } else {
                assert_eq!(
                    store.get(&user, "s").as_deref(),
                    Some(format!("FRESH{i}").as_str())
                );
            }
        }
    }

    /// Battle: concurrent put/get + sweep.
    #[test]
    fn battle_concurrent_put_get_and_sweep() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let store = Arc::new(PendingMfaStore::new());
        let n = 6usize;
        let barrier = Arc::new(Barrier::new(n));
        let mut handles = Vec::with_capacity(n);
        for t in 0..n {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for i in 0..40 {
                    let u = format!("battle-{t}");
                    let s = format!("sess-{i}");
                    store.put(&u, &s, format!("sec-{t}-{i}"));
                    let _ = store.get(&u, &s);
                    if i % 5 == 0 {
                        store.sweep();
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        store.sweep();
        assert!(store.len() <= n * 40);
    }
}
