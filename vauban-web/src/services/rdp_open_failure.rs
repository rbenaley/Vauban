//! What vauban-web says when the RDP proxy could not open a session or
//! fetch a certificate, outside the NLA leg ([`RdpOpenFailure`]).
//!
//! The proxy answers with a closed-set code. The text of the underlying
//! error (a TLS alert, an I/O error, something the target sent) stays in
//! the proxy's log. This module is the only place that turns a code into
//! words, and every message is a constant: nothing that came from the
//! target, the proxy or the request reaches the browser.
//!
//! A value that is not a code (an older proxy, a corrupted field) is not
//! trusted as text. It is read as [`RdpOpenFailure::Internal`].

use shared::messages::RdpOpenFailure;

/// Shown when the web tier could not reach the target or the proxy for a
/// reason of its own (supervisor, IPC), where no code exists.
pub const UNREACHABLE_MESSAGE: &str =
    "The bastion could not reach the target. See the server logs for this session.";

/// Shown when the certificate of a target could not be fetched.
pub const CERT_FETCH_MESSAGE: &str =
    "The server certificate could not be fetched. See the server logs.";

/// The sentence for a code.
///
/// EXHAUSTIVE match (no `_` arm): a new code does not compile until it
/// has a message.
pub const fn message(failure: RdpOpenFailure) -> &'static str {
    match failure {
        RdpOpenFailure::AccessDenied => "Access denied.",
        RdpOpenFailure::Draining => {
            "The RDP service is restarting and takes no new session. Try again in a moment."
        }
        RdpOpenFailure::NoPinnedCertificate => {
            "This asset has no pinned RDP server certificate. An administrator must fetch and pin it before a session can open."
        }
        RdpOpenFailure::CredentialsUnavailable => {
            "The bastion could not obtain the credentials of this target. Contact an administrator of this asset."
        }
        RdpOpenFailure::ServerCertificateMismatch => {
            "The target presented a certificate that is not the pinned one. The session was refused. An administrator must check the change and pin the new certificate."
        }
        RdpOpenFailure::TlsFailed => {
            "The TLS handshake with the target failed. See the vauban-proxy-rdp log for this session."
        }
        RdpOpenFailure::ConnectionFailed => {
            "The connection to the target failed. See the vauban-proxy-rdp log for this session."
        }
        RdpOpenFailure::SessionFailed => {
            "The RDP session could not be established. See the vauban-proxy-rdp log for this session."
        }
        RdpOpenFailure::Internal => {
            "The RDP connection failed. See the vauban-proxy-rdp log for this session."
        }
    }
}

/// The sentence for the `error` field of a proxy answer.
pub fn message_from_wire(code: Option<&str>) -> &'static str {
    message(RdpOpenFailure::from_wire(code))
}

/// Whether the `error` field of a proxy answer says the pinned certificate
/// did not match. Exact code only: a text that merely mentions a mismatch
/// does not count, so nothing the target sends can set the flag.
pub fn is_certificate_mismatch(code: Option<&str>) -> bool {
    code.and_then(RdpOpenFailure::parse) == Some(RdpOpenFailure::ServerCertificateMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_code_has_its_own_constant_message() {
        let mut seen = std::collections::HashSet::new();
        for failure in RdpOpenFailure::ALL {
            let text = message(failure);
            assert!(!text.is_empty());
            assert!(seen.insert(text), "{failure:?} shares a message");
            assert!(
                !text.contains('{') && !text.contains('<'),
                "{failure:?}: a message is plain constant text"
            );
        }
    }

    #[test]
    fn attack_proxy_error_text_is_not_reflected() {
        for text in [
            "<script>alert(1)</script>",
            "RDP session error: target said: <b>pwned</b>",
            "TLS upgrade failed: received fatal alert: \"; drop",
            "Access denied",
            "access_denied\r\nSet-Cookie: x=y",
            "",
        ] {
            let shown = message_from_wire(Some(text));
            assert_eq!(shown, message(RdpOpenFailure::Internal), "{text:?}");
            assert!(!shown.contains(text) || text.is_empty());
        }
        assert_eq!(message_from_wire(None), message(RdpOpenFailure::Internal));
    }

    /// The RDP web handlers answer with constants only: no error value is
    /// passed to the HTMX error response, and none is formatted into it.
    #[test]
    fn attack_rdp_handlers_never_pass_error_text_to_the_browser() {
        let src = include_str!("../handlers/web/rdp.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            !prod.contains("htmx_error_response(&"),
            "an RDP handler passes a variable to htmx_error_response"
        );
        for (i, _) in prod.match_indices("htmx_error_response(") {
            let arg = &prod[i + "htmx_error_response(".len()..];
            let arg = arg.trim_start();
            assert!(
                arg.starts_with('"')
                    || arg.starts_with("crate::services::rdp_open_failure::")
                    || arg.starts_with("crate::services::rdp_auth_failure::")
                    // An ALL_CAPS constant of the parent module.
                    || arg.strip_prefix("super::").is_some_and(|rest| {
                        rest.chars()
                            .take_while(|c| *c != ')')
                            .all(|c| c.is_ascii_uppercase() || c == '_')
                    })
                    || arg.starts_with("message: &str")
                    || arg.starts_with("msg)")
                    || arg.starts_with("message)"),
                "htmx_error_response is called with something that is not a constant: {}",
                &arg[..arg.len().min(60)]
            );
        }
        assert!(
            !prod.contains("error.contains(\"MITM\")")
                && !prod.contains("contains(\"certificate mismatch\")"),
            "a certificate mismatch is decided on the typed code, not on text"
        );
    }

    #[test]
    fn test_known_code_selects_its_message() {
        for failure in RdpOpenFailure::ALL {
            assert_eq!(message_from_wire(Some(failure.as_str())), message(failure));
        }
    }

    #[test]
    fn attack_text_mentioning_a_mismatch_does_not_flag_the_asset() {
        for text in [
            "RDP server certificate mismatch - possible MITM",
            "certificate mismatch",
            "MITM",
            "server_certificate_mismatch ",
            "SERVER_CERTIFICATE_MISMATCH",
            "tls_failed",
        ] {
            assert!(!is_certificate_mismatch(Some(text)), "{text:?}");
        }
        assert!(!is_certificate_mismatch(None));
        assert!(is_certificate_mismatch(Some("server_certificate_mismatch")));
    }
}
