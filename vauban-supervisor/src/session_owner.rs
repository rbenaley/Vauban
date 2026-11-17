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
//! - **INV-2** the table is bounded. The oldest entry is evicted first;
//!   a lease on an evicted or unknown session is refused (fail closed).
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
    owners: HashMap<String, String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl SessionOwners {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            owners: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Record that `session_id` is served by `service_key`.
    ///
    /// Returns `false`, and changes nothing, when the session is already
    /// recorded for another service (INV-1). Recording the same pair
    /// again is accepted: IACS and MCP present one token many times.
    pub fn record(&mut self, session_id: &str, service_key: &str) -> bool {
        if let Some(owner) = self.owners.get(session_id) {
            return owner == service_key;
        }
        while self.owners.len() >= self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.owners.remove(&oldest);
                }
                None => break,
            }
        }
        self.owners
            .insert(session_id.to_string(), service_key.to_string());
        self.order.push_back(session_id.to_string());
        true
    }

    /// The service that serves `session_id`, when known.
    pub fn owner(&self, session_id: &str) -> Option<&str> {
        self.owners.get(session_id).map(String::as_str)
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
                let before = owners.owner(&session).map(str::to_string);
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
