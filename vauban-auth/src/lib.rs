// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! Reusable authentication primitives for `vauban-auth`.
//!
//! This library hosts the logic that must be exercised by both the sandboxed
//! binary AND the integration tests, primarily the LDAPS/AD bind path:
//! a hand-rolled, dependency-light BER codec for the LDAP simple
//! bind, plus the synchronous rustls glue that runs the bind over a
//! supervisor-brokered TCP socket.
//!
//! Design constraints (see `docs/technical/Vauban_LDAPS_Auth_Architecture`):
//! * NO async runtime (`vauban-auth` is a single-threaded, CPU-bound service).
//! * NO `ldap3` (drags tokio + a large BER surface); we only ever issue a
//!   simple bind and read its result code.
//! * Fail-closed parsing: every malformed / truncated / oversized response is
//!   an `io::Error`, never a panic.

pub mod bind;
pub mod ldap;
pub mod tls;

pub use ldap::{LDAP_INVALID_CREDENTIALS, LDAP_SUCCESS, simple_bind_on_stream};

/// Parse an `ldaps://host[:port]` URL into a `(host, port)` couple (default
/// LDAPS port 636). Mirrors the supervisor's `LdapConfig::endpoint`. Returns
/// `None` for any non-`ldaps://` scheme or empty host (fail-closed). Bracketed
/// IPv6 literals are supported.
#[must_use]
pub fn parse_ldaps_endpoint(url: &str) -> Option<(String, u16)> {
    let rest = url.strip_prefix("ldaps://")?;
    let authority = rest.split(['/', '?']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    if let Some(after) = authority.strip_prefix('[') {
        let (host, tail) = after.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        return match tail.strip_prefix(':') {
            Some(p) => Some((host.to_string(), p.parse().ok()?)),
            None if tail.is_empty() => Some((host.to_string(), 636)),
            None => None,
        };
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => {
            if h.is_empty() {
                return None;
            }
            Some((h.to_string(), p.parse().ok()?))
        }
        None => Some((authority.to_string(), 636)),
    }
}

/// Map an LDAP bind result code to the wire outcome returned to vauban-web.
///
/// Only `0` (success) is a success; every other bind-level result code
/// (`49` invalidCredentials, but also `50`/`53`/... ) collapses to
/// [`LdapBindOutcome::InvalidCredentials`]. Transport failures (TCP / TLS)
/// are detected as `io::Error`s by the caller and mapped to `Unreachable` /
/// `TlsError` there, never here.
#[must_use]
pub fn outcome_from_result_code(code: i64) -> shared::messages::LdapBindOutcome {
    use shared::messages::LdapBindOutcome;
    if code == LDAP_SUCCESS {
        LdapBindOutcome::Success
    } else {
        LdapBindOutcome::InvalidCredentials
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::messages::LdapBindOutcome;

    #[test]
    fn parse_endpoint_host_and_port() {
        assert_eq!(
            parse_ldaps_endpoint("ldaps://dc.example.com:3269"),
            Some(("dc.example.com".to_string(), 3269))
        );
        assert_eq!(
            parse_ldaps_endpoint("ldaps://dc.example.com"),
            Some(("dc.example.com".to_string(), 636))
        );
    }

    #[test]
    fn parse_endpoint_rejects_plaintext_and_empty() {
        assert_eq!(parse_ldaps_endpoint("ldap://dc.example.com"), None);
        assert_eq!(parse_ldaps_endpoint(""), None);
        assert_eq!(parse_ldaps_endpoint("ldaps://"), None);
    }

    #[test]
    fn outcome_mapping() {
        assert_eq!(outcome_from_result_code(0), LdapBindOutcome::Success);
        assert_eq!(
            outcome_from_result_code(49),
            LdapBindOutcome::InvalidCredentials
        );
        assert_eq!(
            outcome_from_result_code(53),
            LdapBindOutcome::InvalidCredentials
        );
    }
}
