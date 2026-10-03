//! SPKI pin compare. The presented key is never the trust anchor:
//! it is hashed and compared to the pin the operator already holds.

/// `true` only when `presented_sha256_b64` equals the pin body.
///
/// `expected` is `SHA256:<standard-base64>`. A missing or malformed pin
/// refuses. An attacker who swaps the certificate cannot pass this
/// check: the test `attack_tunnel_spki_mismatch_is_rejected` sends a
/// different digest and expects a refusal.
pub fn spki_matches(expected: &str, presented_sha256_b64: &str) -> bool {
    shared::tls_pin::pins_match(expected, presented_sha256_b64)
}

pub fn format_pin(sha256_b64: &str) -> String {
    format!("SHA256:{sha256_b64}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_pin_is_accepted() {
        assert!(spki_matches("SHA256:aaaa", "aaaa"));
    }

    #[test]
    fn attack_tunnel_spki_mismatch_is_rejected() {
        assert!(!spki_matches("SHA256:aaaa", "bbbb"));
        assert!(!spki_matches("aaaa", "aaaa"));
        assert!(!spki_matches("SHA256:", "aaaa"));
        assert!(!spki_matches("SHA256:aaaa", ""));
    }
}
