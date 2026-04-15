//! TOTP configuration constants shared across Vauban services.
//!
//! Centralizes TOTP parameters so they remain consistent between
//! `vauban-vault` (server-side verification) and `vauban-web` (secret
//! generation, QR codes, fallback verification).

/// Number of digits in a TOTP code.
pub const TOTP_DIGITS: usize = 6;

/// Skew (tolerance) in number of time steps.
/// `0` means only the current 30-second window is accepted.
pub const TOTP_SKEW: u8 = 0;

/// Time step duration in seconds.
pub const TOTP_STEP: u64 = 30;

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-06 regression: TOTP skew must remain at 0 (current window only).
    /// A skew > 0 would allow expired codes to be accepted, widening
    /// the attack surface for real-time TOTP interception (phishing relay).
    #[test]
    fn test_sec06_totp_skew_must_be_zero() {
        assert_eq!(
            TOTP_SKEW, 0,
            "SEC-06: TOTP_SKEW must be 0 to reject expired codes"
        );
    }

    #[test]
    fn test_totp_digits_is_six() {
        assert_eq!(TOTP_DIGITS, 6);
    }

    #[test]
    fn test_totp_step_is_thirty_seconds() {
        assert_eq!(TOTP_STEP, 30);
    }
}
