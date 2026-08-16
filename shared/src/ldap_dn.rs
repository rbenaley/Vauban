//! Fail-closed bind-DN construction for LDAPS simple bind.
//!
//! The directory interprets the bind name as an RFC 4514 distinguished
//! name (or a UPN). Interpolating a raw login identifier into
//! `dn_template` with `str::replace` lets a caller steer the bind into
//! another tree (`alice,ou=admins,...`). Every substitution MUST go
//! through [`substitute_bind_dn`]: the username is allowlisted first,
//! then `{username}` is replaced exactly once.
//!
//! The allowlist matches local account creation
//! (`^[A-Za-z0-9][A-Za-z0-9._-]*$`). RFC 4514 specials
//! (`, = + " \ < > # ;` and surrounding whitespace) are therefore
//! rejected, as is `{` (placeholder injection).

/// Error raised when a bind DN cannot be built fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BindDnError {
    /// Username carries a character that is not in the bind allowlist.
    #[error("username is not allowed in a bind DN")]
    IllegalUsername,
    /// Operator template does not contain the `{username}` placeholder.
    #[error("dn_template does not contain {{username}}")]
    MissingPlaceholder,
}

/// Whether `username` may be interpolated into a bind-DN template.
///
/// Accepts the same charset as local account creation: first character
/// ASCII alphanumeric, remainder ASCII alphanumeric / `.` / `_` / `-`.
/// Empty strings and any RFC 4514 special are rejected.
#[must_use]
pub fn username_allowed_in_bind_dn(username: &str) -> bool {
    let mut chars = username.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Build the LDAP bind name from `dn_template` and a typed username.
///
/// Returns [`BindDnError::IllegalUsername`] without touching the
/// template when the identifier is not allowlisted.
/// Returns [`BindDnError::MissingPlaceholder`] when the operator
/// template forgot `{username}` (a constant DN would otherwise bind
/// every caller as the same entry).
pub fn substitute_bind_dn(template: &str, username: &str) -> Result<String, BindDnError> {
    if !username_allowed_in_bind_dn(username) {
        return Err(BindDnError::IllegalUsername);
    }
    if !template.contains("{username}") {
        return Err(BindDnError::MissingPlaceholder);
    }
    Ok(template.replace("{username}", username))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DN_TEMPLATE: &str = "uid={username},ou=people,dc=example,dc=com";
    const UPN_TEMPLATE: &str = "{username}@example.com";

    #[test]
    fn accepts_alice() {
        assert_eq!(
            substitute_bind_dn(DN_TEMPLATE, "alice").unwrap(),
            "uid=alice,ou=people,dc=example,dc=com"
        );
    }

    #[test]
    fn accepts_jean_dupont() {
        assert_eq!(
            substitute_bind_dn(DN_TEMPLATE, "Jean-Dupont").unwrap(),
            "uid=Jean-Dupont,ou=people,dc=example,dc=com"
        );
    }

    #[test]
    fn accepts_dots_and_underscores() {
        assert_eq!(
            substitute_bind_dn(UPN_TEMPLATE, "user.name_1").unwrap(),
            "user.name_1@example.com"
        );
    }

    #[test]
    fn rejects_comma_steer() {
        assert_eq!(
            substitute_bind_dn(DN_TEMPLATE, "alice,ou=admins"),
            Err(BindDnError::IllegalUsername)
        );
    }

    #[test]
    fn rejects_rfc4514_specials() {
        for bad in [
            ",", "=", "+", "\"", "\\", "<", ">", "#", ";", " alice", "alice ",
        ] {
            assert!(
                !username_allowed_in_bind_dn(bad),
                "special {bad:?} must be rejected"
            );
            assert_eq!(
                substitute_bind_dn(DN_TEMPLATE, bad),
                Err(BindDnError::IllegalUsername),
                "special {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_placeholder_injection() {
        assert_eq!(
            substitute_bind_dn(DN_TEMPLATE, "alice{username}"),
            Err(BindDnError::IllegalUsername)
        );
    }

    #[test]
    fn rejects_empty_and_at_sign() {
        assert_eq!(
            substitute_bind_dn(DN_TEMPLATE, ""),
            Err(BindDnError::IllegalUsername)
        );
        assert_eq!(
            substitute_bind_dn(DN_TEMPLATE, "alice@corp"),
            Err(BindDnError::IllegalUsername)
        );
    }

    #[test]
    fn rejects_missing_placeholder() {
        assert_eq!(
            substitute_bind_dn("uid=static,ou=people,dc=example,dc=com", "alice"),
            Err(BindDnError::MissingPlaceholder)
        );
    }

    #[test]
    fn username_allowed_matches_local_creation_regex() {
        assert!(username_allowed_in_bind_dn("a"));
        assert!(username_allowed_in_bind_dn("A0._-z"));
        assert!(!username_allowed_in_bind_dn(".leading-dot"));
        assert!(!username_allowed_in_bind_dn("_leading"));
    }
}
