//! Shared SMTP helpers used by vauban-web (outbox INSERT) and
//! vauban-mailer (wire emission). Keeps CRLF injection defense in
//! one place.

/// Error returned when a caller-controlled SMTP/header string contains CR or LF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("CRLF injection detected in {field}")]
pub struct CrlfInjectionError {
    pub field: &'static str,
}

/// Refuse caller-controlled strings that contain `\r` or `\n`.
pub fn validate_no_crlf(field: &'static str, value: &str) -> Result<(), CrlfInjectionError> {
    if value.bytes().any(|b| b == b'\r' || b == b'\n') {
        return Err(CrlfInjectionError { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_no_crlf_rejects_cr_and_lf() {
        assert!(validate_no_crlf("subject", "a\rb").is_err());
        assert!(validate_no_crlf("subject", "a\nb").is_err());
        validate_no_crlf("subject", "clean").unwrap();
    }
}
