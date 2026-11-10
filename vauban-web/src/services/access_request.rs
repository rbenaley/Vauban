//! Shared rules for a JIT access request.
//!
//! An access request is a `proxy_sessions` row in status `pending`. It
//! is listed under `/sessions/approvals` and decided in `vauban-access`.
//! Two surfaces create one: the web form
//! (`handlers::web::sessions::submit_access_request`) and the M2M API
//! (`handlers::api::sessions::create_session`). Both MUST build the row
//! from the helpers below so that a request carries the same guarantees
//! whichever door it came through:
//!
//! * the credential columns hold the [`PENDING_CREDENTIAL`] placeholder,
//!   never a caller-supplied value;
//! * the justification went through [`normalize_justification`];
//! * `max_session_duration` is copied from the access-rule evaluation,
//!   so the approval computes an `expires_at` horizon.

/// Minimum length, in bytes after trimming, of a request justification.
pub const MIN_JUSTIFICATION_LEN: usize = 10;

/// User-facing refusal when the justification is missing or too short.
pub const JUSTIFICATION_REQUIRED_MESSAGE: &str =
    "Justification is required (minimum 10 characters)";

/// Placeholder stored in `credential_id` / `credential_username` while a
/// request is pending. The real credential is resolved when the approved
/// grant is consumed by a connect handler.
pub const PENDING_CREDENTIAL: &str =
    crate::templates::sessions::presentation::PENDING_CREDENTIAL_ID;

/// Validate and sanitize a request justification.
///
/// Returns `None` when the value is absent, or shorter than
/// [`MIN_JUSTIFICATION_LEN`] bytes once trimmed, or shorter than that
/// once every HTML tag has been stripped (a justification made only of
/// markup carries no reviewable text). Otherwise returns the trimmed,
/// tag-free text ready to persist.
pub fn normalize_justification(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    if trimmed.len() < MIN_JUSTIFICATION_LEN {
        return None;
    }
    let clean = crate::handlers::web::sanitize(trimmed);
    let clean = clean.trim();
    if clean.len() < MIN_JUSTIFICATION_LEN {
        return None;
    }
    Some(clean.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_justification_absent_returns_none() {
        assert_eq!(normalize_justification(None), None);
    }

    #[test]
    fn test_normalize_justification_too_short_returns_none() {
        for raw in ["", "   ", "short", "123456789", "  123456789  "] {
            assert_eq!(normalize_justification(Some(raw)), None, "input: {raw:?}");
        }
    }

    #[test]
    fn test_normalize_justification_minimum_length_is_accepted() {
        assert_eq!(
            normalize_justification(Some("1234567890")),
            Some("1234567890".to_string())
        );
    }

    #[test]
    fn test_normalize_justification_trims_surrounding_whitespace() {
        assert_eq!(
            normalize_justification(Some("  routine maintenance \n")),
            Some("routine maintenance".to_string())
        );
    }

    #[test]
    fn test_normalize_justification_strips_html_tags() {
        let out = normalize_justification(Some("<b>routine</b> maintenance window"));
        assert_eq!(out, Some("routine maintenance window".to_string()));
    }

    #[test]
    fn test_normalize_justification_markup_only_is_rejected() {
        // 30+ bytes of markup, zero bytes of reviewable text.
        assert_eq!(
            normalize_justification(Some("<script></script><b></b><i></i>")),
            None
        );
    }

    #[test]
    fn test_pending_credential_matches_presentation_constant() {
        assert_eq!(PENDING_CREDENTIAL, "pending");
        assert!(crate::templates::sessions::presentation::is_jit_grant(
            PENDING_CREDENTIAL
        ));
    }

    #[test]
    fn test_justification_message_states_the_minimum() {
        assert!(JUSTIFICATION_REQUIRED_MESSAGE.contains(&MIN_JUSTIFICATION_LEN.to_string()));
    }
}
