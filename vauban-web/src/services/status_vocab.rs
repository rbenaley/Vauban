//! Closed status vocabularies for the list pages.
//!
//! The July 2026 audit found that every list duplicated its status
//! vocabulary in three places (the template `<select>` options, the
//! handler `status.eq(...)` literals, the display labels) with
//! nothing keeping the copies aligned: `/sessions` had no `expired`
//! option, offered a dead `pending` option (structurally excluded by
//! the handler) plus the phantom `completed` status, `/assets*`
//! lacked `unknown`, `/audit/approvals` lagged one migration behind
//! its `decision` CHECK. This module is the single source of truth:
//! handlers sanitize the query param through [`StatusVocab::sanitize`],
//! templates render their options from [`StatusVocab::options`], and
//! the drift tests in `tests/web/status_vocab_drift_test.rs` pin the
//! vocabularies against `SessionStatus::ALL`, the DB CHECK migration
//! and the rendered pages.

/// A closed `(value, label)` status vocabulary for one list page.
pub struct StatusVocab {
    pub entries: &'static [(&'static str, &'static str)],
}

impl StatusVocab {
    /// Whether `value` belongs to the vocabulary.
    #[must_use]
    pub fn contains(&self, value: &str) -> bool {
        self.entries.iter().any(|(v, _)| *v == value)
    }

    /// Fail-open sanitizer for the `?status=` query param: members
    /// pass through unchanged, anything else (tampered / stale URL)
    /// degrades to "no filter" instead of a confusing empty list.
    /// Also anti-oracle: an unknown value produces exactly the same
    /// view as no filter at all.
    #[must_use]
    pub fn sanitize(&self, raw: Option<String>) -> Option<String> {
        raw.filter(|s| self.contains(s))
    }

    /// Owned `(value, label)` couples for the template `<select>`.
    #[must_use]
    pub fn options(&self) -> Vec<(String, String)> {
        self.entries
            .iter()
            .map(|(v, l)| ((*v).to_string(), (*l).to_string()))
            .collect()
    }

    /// The raw values (drift tests, E2E seeding).
    #[must_use]
    pub fn values(&self) -> Vec<&'static str> {
        self.entries.iter().map(|(v, _)| *v).collect()
    }
}

/// `/sessions` history list. `pending` and `orphaned` are
/// structurally excluded by the handler (they belong to the approval
/// queue), so they get no option. The IACS statuses live in
/// [`SESSION_HISTORY_IACS`] and are appended only when the
/// industrial kill-switch is on (see [`session_history_options`]).
pub const SESSION_HISTORY: StatusVocab = StatusVocab {
    entries: &[
        ("active", "Active"),
        ("connecting", "Connecting"),
        ("disconnected", "Disconnected"),
        ("terminated", "Terminated"),
        ("expired", "Expired"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
        ("revoked", "Revoked"),
    ],
};

/// IACS-only statuses appended to [`SESSION_HISTORY`] when
/// `industrial.enabled = true` (mirror of `AssetType::filter_options`).
pub const SESSION_HISTORY_IACS: StatusVocab = StatusVocab {
    entries: &[
        ("waiting_client", "Waiting client"),
        ("tunnel_active", "Tunnel active"),
    ],
};

/// Select options for the `/sessions` status filter, kill-switch
/// aware. The sanitizer counterpart is [`session_history_sanitize`]:
/// both MUST derive from the same pair of vocabularies.
#[must_use]
pub fn session_history_options(industrial_enabled: bool) -> Vec<(String, String)> {
    let mut out = SESSION_HISTORY.options();
    if industrial_enabled {
        out.extend(SESSION_HISTORY_IACS.options());
    }
    out
}

/// Fail-open sanitizer for the `/sessions` status filter. IACS
/// statuses stay accepted even when the kill-switch is off: the DB
/// query already excludes IACS rows (layer 2), so the filter is
/// inert rather than an oracle.
#[must_use]
pub fn session_history_sanitize(raw: Option<String>) -> Option<String> {
    raw.filter(|s| SESSION_HISTORY.contains(s) || SESSION_HISTORY_IACS.contains(s))
}

/// `/sessions/approvals` queue. Session-state statuses (connecting,
/// active, terminated, disconnected) are excluded by design -- they
/// belong in the session list, not the approval queue.
pub const APPROVAL: StatusVocab = StatusVocab {
    entries: &[
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
        ("revoked", "Revoked"),
        ("expired", "Expired"),
        ("orphaned", "Orphaned"),
    ],
};

/// `/sessions/my-requests` Access tab (self-service JIT lifecycle).
/// Labels match the row badges of `MyRequestItem::status_label`.
pub const MY_REQUESTS: StatusVocab = StatusVocab {
    entries: &[
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
        ("revoked", "Revoked"),
        ("expired", "Expired"),
        ("active", "Connected"),
        ("disconnected", "Completed"),
        ("terminated", "Terminated"),
    ],
};

/// `/audit/approvals` decision filter. Kept in lock-step with the
/// `approval_audit_log.decision` CHECK constraint (migration
/// `20260705000000_jit_grant_revocation`).
pub const AUDIT_DECISIONS: StatusVocab = StatusVocab {
    entries: &[
        ("approve", "Approved"),
        ("reject", "Rejected"),
        ("revoke", "Revoked"),
        ("update_duration", "Duration updated"),
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_member_passes_through() {
        assert_eq!(
            APPROVAL.sanitize(Some("pending".to_string())),
            Some("pending".to_string())
        );
    }

    #[test]
    fn test_sanitize_unknown_degrades_to_no_filter() {
        assert_eq!(APPROVAL.sanitize(Some("bogus".to_string())), None);
        assert_eq!(APPROVAL.sanitize(None), None);
    }

    #[test]
    fn test_session_history_options_gate_iacs_on_kill_switch() {
        let with = session_history_options(true);
        let without = session_history_options(false);
        assert!(with.iter().any(|(v, _)| v == "tunnel_active"));
        assert!(with.iter().any(|(v, _)| v == "waiting_client"));
        assert!(!without.iter().any(|(v, _)| v == "tunnel_active"));
        assert!(!without.iter().any(|(v, _)| v == "waiting_client"));
        assert_eq!(with.len(), without.len() + 2);
    }

    #[test]
    fn test_session_history_sanitize_accepts_iacs_regardless_of_switch() {
        assert_eq!(
            session_history_sanitize(Some("tunnel_active".to_string())),
            Some("tunnel_active".to_string())
        );
        assert_eq!(
            session_history_sanitize(Some("completed".to_string())),
            None
        );
        assert_eq!(session_history_sanitize(Some("pending".to_string())), None);
    }

    #[test]
    fn test_phantom_statuses_are_gone() {
        for vocab in [&SESSION_HISTORY, &APPROVAL, &MY_REQUESTS] {
            assert!(!vocab.contains("completed"));
            assert!(!vocab.contains("consumed"));
        }
    }
}
