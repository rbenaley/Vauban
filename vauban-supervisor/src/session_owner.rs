//! Which service serves which session.
//!
//! The supervisor verifies a signed `SessionToken` before it brokers the
//! TCP connection of a session to its proxy. The token names the session
//! and the service it was minted for, and no sandboxed service can forge
//! one. This table keeps that fact: once the token of session S has been
//! accepted for service X, S is served by X.
//!
//! The file broker reads it back: a proxy obtains a write lease only on a
//! session recorded under its own name, and the audit service obtains a
//! metadata lease only on behalf of the proxy that serves the session.
//!
//! # Invariants
//!
//! - **INV-1** an entry never changes service. A second token for the
//!   same session and another service is refused.
//! - **INV-2** the table is bounded. The least recently used session is
//!   evicted first (an accepted token and a granted lease count as a
//!   use, a refused request does not); a lease on an evicted or unknown
//!   session is refused (fail closed).
//! - **INV-3** nothing but an accepted token writes to the table.
//!
//! The table lives in memory. The services, and with them every session,
//! do not outlive the supervisor, so nothing is lost that is still used.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};

/// Sessions remembered at once. A session costs roughly a hundred bytes;
/// a bastion that opened this many sessions since the last restart has
/// long closed the oldest ones.
pub const MAX_SESSIONS: usize = 262_144;

#[derive(Debug)]
pub struct SessionOwners {
    /// Session -> (service, stamp of its last use).
    owners: HashMap<String, (String, u64)>,
    /// Uses in order, oldest first. An entry whose stamp is no longer
    /// the session's current one is stale and skipped.
    order: VecDeque<(String, u64)>,
    capacity: usize,
    next_stamp: u64,
}

impl SessionOwners {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            owners: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
            next_stamp: 0,
        }
    }

    /// Mark `session_id` as just used, so it is the last to be evicted.
    fn touch(&mut self, session_id: &str) {
        let Some((_, stamp)) = self.owners.get_mut(session_id) else {
            return;
        };
        self.next_stamp += 1;
        *stamp = self.next_stamp;
        self.order
            .push_back((session_id.to_string(), self.next_stamp));
        // Stale entries pile up with every use; drop them once they
        // outnumber the live ones.
        if self.order.len() > self.capacity.saturating_mul(2).saturating_add(16) {
            let owners = &self.owners;
            self.order
                .retain(|(id, stamp)| owners.get(id).is_some_and(|(_, current)| current == stamp));
        }
    }

    /// Drop the least recently used session.
    fn evict_one(&mut self) {
        while let Some((id, stamp)) = self.order.pop_front() {
            if self
                .owners
                .get(&id)
                .is_some_and(|(_, current)| *current == stamp)
            {
                self.owners.remove(&id);
                return;
            }
        }
    }

    /// Record that `session_id` is served by `service_key`.
    ///
    /// Returns `false`, and changes nothing, when the session is already
    /// recorded for another service (INV-1). Recording the same pair
    /// again is accepted: IACS and MCP present one token many times.
    pub fn record(&mut self, session_id: &str, service_key: &str) -> bool {
        if let Some((owner, _)) = self.owners.get(session_id) {
            let same = owner == service_key;
            if same {
                self.touch(session_id);
            }
            return same;
        }
        while self.owners.len() >= self.capacity {
            let before = self.owners.len();
            self.evict_one();
            if self.owners.len() == before {
                break;
            }
        }
        self.owners
            .insert(session_id.to_string(), (service_key.to_string(), 0));
        self.touch(session_id);
        true
    }

    /// The service that serves `session_id`, when known. A lookup is
    /// not a use: a request that is then refused must not keep the
    /// session it names alive, or a service could pin its own sessions
    /// in the table and push those of others out.
    pub fn owner(&self, session_id: &str) -> Option<&str> {
        self.owners
            .get(session_id)
            .map(|(service, _)| service.as_str())
    }

    /// Mark `session_id` as used: a lease on it was granted. A session
    /// that keeps obtaining files is not the one evicted when the table
    /// is full.
    pub fn used(&mut self, session_id: &str) {
        self.touch(session_id);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.owners.len()
    }
}

static SESSION_OWNERS: OnceLock<Mutex<SessionOwners>> = OnceLock::new();

fn table() -> &'static Mutex<SessionOwners> {
    SESSION_OWNERS.get_or_init(|| Mutex::new(SessionOwners::with_capacity(MAX_SESSIONS)))
}

/// Record an accepted token. `false` when the session belongs to another
/// service, or when the table cannot be locked (fail closed).
pub fn record(session_id: &str, service_key: &str) -> bool {
    table()
        .lock()
        .map(|mut owners| owners.record(session_id, service_key))
        .unwrap_or(false)
}

/// The service that serves `session_id`. `None` when unknown, evicted,
/// or when the table cannot be locked.
pub fn owner(session_id: &str) -> Option<String> {
    table()
        .lock()
        .ok()
        .and_then(|owners| owners.owner(session_id).map(str::to_string))
}

/// A lease on `session_id` was granted: keep it among the last evicted.
pub fn used(session_id: &str) {
    if let Ok(mut owners) = table().lock() {
        owners.used(session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_first_token_sets_the_owner() {
        let mut owners = SessionOwners::with_capacity(8);
        assert_eq!(owners.owner("s1"), None);
        assert!(owners.record("s1", "proxy_ssh"));
        assert_eq!(owners.owner("s1"), Some("proxy_ssh"));
    }

    #[test]
    fn test_same_service_may_present_the_token_again() {
        let mut owners = SessionOwners::with_capacity(8);
        assert!(owners.record("s1", "proxy_iacs"));
        assert!(owners.record("s1", "proxy_iacs"));
        assert_eq!(owners.len(), 1);
    }

    #[test]
    fn attack_second_service_claiming_a_session_is_rejected() {
        let mut owners = SessionOwners::with_capacity(8);
        assert!(owners.record("s1", "proxy_rdp"));
        assert!(!owners.record("s1", "proxy_ssh"));
        assert!(!owners.record("s1", "proxy_mcp"));
        assert_eq!(owners.owner("s1"), Some("proxy_rdp"));
    }

    #[test]
    fn test_oldest_session_is_evicted_at_capacity() {
        let mut owners = SessionOwners::with_capacity(2);
        assert!(owners.record("s1", "proxy_ssh"));
        assert!(owners.record("s2", "proxy_ssh"));
        assert!(owners.record("s3", "proxy_rdp"));
        assert_eq!(owners.len(), 2);
        assert_eq!(owners.owner("s1"), None, "evicted: unknown, so refused");
        assert_eq!(owners.owner("s2"), Some("proxy_ssh"));
        assert_eq!(owners.owner("s3"), Some("proxy_rdp"));
    }

    /// A session that keeps asking for files outlives newer idle ones.
    /// Eviction used to follow insertion order: a long RDP session lost
    /// its entry, and its next segment, once enough sessions had been
    /// opened after it.
    #[test]
    fn test_session_in_use_is_not_the_one_evicted() {
        let mut owners = SessionOwners::with_capacity(3);
        assert!(owners.record("long", "proxy_rdp"));
        assert!(owners.record("idle-1", "proxy_ssh"));
        assert!(owners.record("idle-2", "proxy_ssh"));
        for n in 0..50 {
            // The long session leases a segment between newer sessions.
            assert_eq!(owners.owner("long"), Some("proxy_rdp"), "round {n}");
            owners.used("long");
            assert!(owners.record(&format!("new-{n}"), "proxy_ssh"));
            assert_eq!(owners.len(), 3);
        }
        assert_eq!(owners.owner("long"), Some("proxy_rdp"));
        assert_eq!(owners.owner("idle-1"), None);
    }

    /// Naming a session in requests that are refused does not keep it in
    /// the table: only a granted lease or an accepted token is a use.
    #[test]
    fn attack_lookups_do_not_keep_a_session_alive() {
        let mut owners = SessionOwners::with_capacity(2);
        assert!(owners.record("hoarded", "proxy_ssh"));
        assert!(owners.record("victim", "proxy_rdp"));
        for _ in 0..100 {
            // What a refused request does: it looks the session up.
            assert_eq!(owners.owner("hoarded"), Some("proxy_ssh"));
        }
        owners.used("victim");
        assert!(owners.record("new", "proxy_mcp"));
        assert_eq!(owners.owner("hoarded"), None, "the idle one is evicted");
        assert_eq!(owners.owner("victim"), Some("proxy_rdp"));
        // A use of a session that is not there changes nothing.
        owners.used("never-seen");
        assert_eq!(owners.len(), 2);
    }

    #[test]
    fn test_use_log_stays_bounded() {
        let mut owners = SessionOwners::with_capacity(4);
        assert!(owners.record("s", "proxy_iacs"));
        for _ in 0..10_000 {
            assert!(owners.record("s", "proxy_iacs"));
            owners.used("s");
        }
        assert!(
            owners.order.len() <= 4 * 2 + 16 + 1,
            "{}",
            owners.order.len()
        );
    }

    #[test]
    fn test_presenting_a_token_again_does_not_grow_the_table() {
        let mut owners = SessionOwners::with_capacity(2);
        assert!(owners.record("s1", "proxy_mcp"));
        for _ in 0..10 {
            assert!(owners.record("s1", "proxy_mcp"));
        }
        assert!(owners.record("s2", "proxy_mcp"));
        assert_eq!(owners.owner("s1"), Some("proxy_mcp"));
    }

    proptest! {
        /// INV-1 and INV-2 under any sequence of tokens: an owner, once
        /// read, is the first service recorded for that session since it
        /// last entered the table, and the table never exceeds its bound.
        #[test]
        fn prop_owner_never_changes_and_table_is_bounded(
            ops in proptest::collection::vec((0u8..12, 0u8..4), 0..200),
            capacity in 1usize..8,
        ) {
            let services = ["proxy_ssh", "proxy_rdp", "proxy_mcp", "proxy_iacs"];
            let mut owners = SessionOwners::with_capacity(capacity);
            for (session, service) in ops {
                let session = format!("s{session}");
                let service = services[service as usize];
                let before = owners.owners.get(&session).map(|(service, _)| service.clone());
                let accepted = owners.record(&session, service);
                match before {
                    Some(owner) => {
                        prop_assert_eq!(accepted, owner == service);
                        prop_assert_eq!(owners.owner(&session), Some(owner.as_str()));
                    }
                    None => {
                        prop_assert!(accepted);
                        prop_assert_eq!(owners.owner(&session), Some(service));
                    }
                }
                prop_assert!(owners.len() <= capacity);
            }
        }
    }
}
