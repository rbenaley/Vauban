//! What vauban-web says when the SSH proxy could not open a session
//! ([`SshOpenFailure`]).
//!
//! The proxy answers with a closed-set code. The text of the underlying
//! error (a russh error, something the target sent) stays in the proxy's
//! log. This module is the only place that turns a code into words, and
//! every message is a constant: nothing that came from the target, the
//! proxy or the request reaches the browser.
//!
//! A value that is not a code (an older proxy, a corrupted field) is not
//! trusted as text. It is read as [`SshOpenFailure::Internal`].

use shared::messages::SshOpenFailure;

/// Shown when the web tier could not reach the target or the proxy for a
/// reason of its own (supervisor, IPC), where no code exists.
pub const UNREACHABLE_MESSAGE: &str =
    "The bastion could not reach the target. See the server logs for this session.";

/// The sentence for a code.
///
/// EXHAUSTIVE match (no `_` arm): a new code does not compile until it
/// has a message.
pub const fn message(failure: SshOpenFailure) -> &'static str {
    match failure {
        SshOpenFailure::AccessDenied => "Access denied.",
        SshOpenFailure::Draining => {
            "The SSH service is restarting and takes no new session. Try again in a moment."
        }
        SshOpenFailure::NoPinnedHostKey => {
            "This asset has no pinned SSH host key. An administrator must fetch and pin it before a session can open."
        }
        SshOpenFailure::CredentialsUnavailable => {
            "The bastion could not obtain the credentials of this target. Contact an administrator of this asset."
        }
        SshOpenFailure::HostKeyMismatch => {
            "The target presented a host key that is not the pinned one. The session was refused. An administrator must check the change and pin the new key."
        }
        SshOpenFailure::HostCertificateRefused => {
            "The target presented an SSH host certificate, which the bastion does not accept. The session was refused."
        }
        SshOpenFailure::AuthenticationFailed => {
            "The target refused the stored credentials. Contact an administrator of this asset."
        }
        SshOpenFailure::ConnectionFailed => {
            "The connection to the target failed. See the vauban-proxy-ssh log for this session."
        }
        SshOpenFailure::SessionFailed => {
            "The SSH session could not be established. See the vauban-proxy-ssh log for this session."
        }
        SshOpenFailure::RemoteCommandFailed => {
            "The command run on the target failed. See the vauban-proxy-ssh log for its output."
        }
        SshOpenFailure::Internal => {
            "The SSH connection failed. See the vauban-proxy-ssh log for this session."
        }
    }
}

/// The error the IPC client returns for a failed one-shot operation
/// (host key fetch, public key push, key authentication test): the
/// constant sentence of the proxy's code, and nothing the proxy wrote.
pub fn ipc_error(code: Option<&str>) -> crate::error::AppError {
    crate::error::AppError::Ipc(message_from_wire(code).to_string())
}

/// The failure an error of the SSH IPC client stands for, when it is
/// one of the proxy's verdicts ([`ipc_error`]). `None` for an error of
/// the web tier itself (supervisor, pipe, timeout).
///
/// The match is on this module's own constant sentences, which are
/// distinct, never on text a proxy or a target wrote.
pub fn of_error(error: &crate::error::AppError) -> Option<SshOpenFailure> {
    match error {
        crate::error::AppError::Ipc(text) => SshOpenFailure::ALL
            .into_iter()
            .find(|failure| message(*failure) == text.as_str()),
        _ => None,
    }
}

/// What to show for a failed one-shot operation: the proxy's verdict,
/// or [`UNREACHABLE_MESSAGE`] when the error is the web tier's own.
pub fn operation_message(error: &crate::error::AppError) -> &'static str {
    of_error(error).map(message).unwrap_or(UNREACHABLE_MESSAGE)
}

/// The sentence for the `error` field of a proxy answer.
pub fn message_from_wire(code: Option<&str>) -> &'static str {
    message(SshOpenFailure::from_wire(code))
}

/// Whether the `error` field of a proxy answer says the pinned host key
/// did not match. Exact code only: a text that merely mentions a host
/// key does not count, so nothing the target sends can set the flag.
pub fn is_host_key_mismatch(code: Option<&str>) -> bool {
    code.and_then(SshOpenFailure::parse) == Some(SshOpenFailure::HostKeyMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_code_has_its_own_constant_message() {
        let mut seen = std::collections::HashSet::new();
        for failure in SshOpenFailure::ALL {
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
    fn test_codes_round_trip_and_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for failure in SshOpenFailure::ALL {
            assert_eq!(SshOpenFailure::parse(failure.as_str()), Some(failure));
            assert!(seen.insert(failure.as_str()));
        }
    }

    /// The detection used to be `msg.contains("host key")`: any text the
    /// proxy relayed could mark the asset, and a reworded error could
    /// stop marking it.
    #[test]
    fn attack_text_mentioning_a_host_key_is_not_a_mismatch() {
        for text in [
            "host key",
            "Host key verification failed",
            "possible MITM",
            "SSH connection failed: Unknown server key",
            "host_key_mismatch ",
            " host_key_mismatch",
            "HOST_KEY_MISMATCH",
            "host_key_mismatch\n",
            "",
        ] {
            assert!(!is_host_key_mismatch(Some(text)), "{text:?}");
        }
        assert!(!is_host_key_mismatch(None));
        assert!(is_host_key_mismatch(Some("host_key_mismatch")));
    }

    #[test]
    fn test_ipc_error_round_trips_to_its_failure() {
        for failure in SshOpenFailure::ALL {
            let error = ipc_error(Some(failure.as_str()));
            assert_eq!(of_error(&error), Some(failure));
            assert_eq!(operation_message(&error), message(failure));
        }
    }

    /// An error of the web tier, or one carrying text that is not one of
    /// the constants, is no verdict: generic sentence, no flag.
    #[test]
    fn attack_ipc_error_text_is_not_shown_nor_taken_for_a_verdict() {
        use crate::error::AppError;
        for text in [
            "host key mismatch",
            "<script>alert(1)</script>",
            "Push public key failed: remote authorized_keys update failed (exit 1): rm -rf",
            "The target presented a host key that is not the pinned one.",
            "",
        ] {
            let error = AppError::Ipc(text.to_string());
            assert_eq!(of_error(&error), None, "{text:?}");
            assert_eq!(operation_message(&error), UNREACHABLE_MESSAGE);
        }
        let proxy_text = ipc_error(Some("stderr of the target: you have been pwned"));
        assert_eq!(of_error(&proxy_text), Some(SshOpenFailure::Internal));
        assert_eq!(
            of_error(&AppError::Validation(
                message(SshOpenFailure::HostKeyMismatch).to_string()
            )),
            None
        );
    }

    /// The SSH web handlers answer with constants only: nothing is
    /// formatted into the HTMX error response, and no error value is
    /// passed to it.
    #[test]
    fn attack_ssh_handlers_never_pass_error_text_to_the_browser() {
        let src = include_str!("../handlers/web/ssh.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            !prod.contains("htmx_error_response(&format!("),
            "an SSH handler formats text into htmx_error_response"
        );
        for needle in ["htmx_error_response(&e)", "htmx_error_response(&err)"] {
            assert!(
                !prod.contains(needle),
                "an SSH handler shows an error value"
            );
        }
        for (i, _) in prod.match_indices("htmx_error_response(") {
            let arg = prod[i + "htmx_error_response(".len()..].trim_start();
            assert!(
                arg.starts_with('"')
                    || arg.starts_with("crate::services::ssh_open_failure::")
                    || arg.starts_with("crate::models::asset::PIN_CHANGED_MESSAGE)")
                    // Constant sentences held in a local.
                    || arg.starts_with("&msg)")
                    || arg.starts_with("msg)")
                    || arg.starts_with("message: &str"),
                "htmx_error_response is called with something that is not a constant: {}",
                &arg[..arg.len().min(60)]
            );
        }
        // The supervisor's text is not shown either.
        assert!(
            !prod
                .contains(r#"unwrap_or_else(|| "Failed to establish TCP connection".to_string())"#)
        );
    }

    #[test]
    fn attack_proxy_error_text_is_not_reflected() {
        for text in [
            "<script>alert(1)</script>",
            "SSH connection failed: banner from target: you have been pwned",
            "Access denied.\", \"type\": \"success",
        ] {
            let shown = message_from_wire(Some(text));
            assert_eq!(shown, message(SshOpenFailure::Internal));
            assert!(!shown.contains(text));
        }
        assert_eq!(message_from_wire(None), message(SshOpenFailure::Internal));
    }
}
