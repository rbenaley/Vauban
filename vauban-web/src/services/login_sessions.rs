//! Pure presentation / authorization rules for login (auth) sessions.
//!
//! The "current session" of a request is its `auth_sessions.uuid`,
//! carried by the JWT `jti` claim and exposed to handlers via the
//! [`crate::middleware::auth::AuthSessionId`] extractor. Identifying
//! the current session by hashing the `access_token` cookie is
//! forbidden here: the cookie is rotated mid-session by
//! `maybe_rotate_access_cookie`, so a hash comparison silently breaks
//! right after a rotation (and a wrong cookie name breaks it always --
//! the production bug where the profile page offered to revoke the
//! caller's own active session).

use uuid::Uuid;

/// Whether a session row is the one authenticating the current request.
#[must_use]
pub fn is_current_session(row_uuid: Uuid, current: Uuid) -> bool {
    row_uuid == current
}

/// Decision of the self-revocation guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfRevocation {
    /// The target is the caller's own current session: refuse. Ending
    /// the current session is what logout is for; revoking it from the
    /// session list leaves the browser on a dead page mid-navigation.
    RefusedCurrentSession,
    /// The target is another session: the revocation may proceed.
    Allowed,
}

/// Fail-closed guard: a caller may never revoke the login session that
/// authenticates the request being processed.
#[must_use]
pub fn self_revocation_guard(target: Uuid, current: Uuid) -> SelfRevocation {
    if target == current {
        SelfRevocation::RefusedCurrentSession
    } else {
        SelfRevocation::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_current_session_true_on_equal_uuid() {
        let id = Uuid::new_v4();
        assert!(is_current_session(id, id));
    }

    #[test]
    fn test_is_current_session_false_on_different_uuid() {
        assert!(!is_current_session(Uuid::new_v4(), Uuid::new_v4()));
    }

    #[test]
    fn test_self_revocation_guard_refuses_own_session() {
        let id = Uuid::new_v4();
        assert_eq!(
            self_revocation_guard(id, id),
            SelfRevocation::RefusedCurrentSession
        );
    }

    #[test]
    fn test_self_revocation_guard_allows_other_session() {
        assert_eq!(
            self_revocation_guard(Uuid::new_v4(), Uuid::new_v4()),
            SelfRevocation::Allowed
        );
    }
}
