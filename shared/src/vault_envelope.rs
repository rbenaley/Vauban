//! Vault ciphertext envelope shape detection (parse-only).
//!
//! Encrypted values produced by `vauban-vault` use the wire form
//! `"v{digits}:{payload}"` (typically base64 after the colon). This module
//! classifies that shape **without** validating base64, decrypting, or
//! touching any key material (I1). Crypto stays exclusively in
//! `vauban-vault`; consumers that only need the plaintext-vs-envelope branch
//! (web MFA / credentials, supervisor `migrate_secrets`) share this single
//! definition (I2).

/// Check whether `value` looks like a vauban-vault versioned envelope.
///
/// Encrypted values have the format `"v{digit(s)}:{non_empty_payload}"`.
/// This function does **not** validate the base64 payload or attempt
/// decryption.
///
/// # Invariants
///
/// - I1: shape-only (no crypto, no base64 decode)
/// - I3: `len >= 4`, prefix `v`, ASCII digits between `v` and `:`,
///   non-empty payload after `:` (so `"v1:"` is rejected via length)
pub fn is_vault_envelope(value: &str) -> bool {
    if value.len() < 4 {
        return false;
    }
    if !value.starts_with('v') {
        return false;
    }
    let Some(colon_pos) = value.find(':') else {
        return false;
    };
    if colon_pos < 2 {
        return false;
    }
    // Non-empty payload after the colon (I3).
    if colon_pos + 1 >= value.len() {
        return false;
    }
    value[1..colon_pos].chars().all(|c| c.is_ascii_digit())
}

/// Extract the version number from a vault envelope, if the shape is valid.
///
/// Still parse-only: does not validate or decode the payload.
pub fn vault_envelope_version(value: &str) -> Option<u32> {
    if !is_vault_envelope(value) {
        return None;
    }
    let colon_pos = value.find(':')?;
    value[1..colon_pos].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn test_is_vault_envelope_valid() {
        assert!(is_vault_envelope("v1:x"));
        assert!(is_vault_envelope("v1:SGVsbG8="));
        assert!(is_vault_envelope("v12:AAAA"));
        assert!(is_vault_envelope("v999:longdata"));
    }

    #[test]
    fn test_is_vault_envelope_invalid() {
        assert!(!is_vault_envelope(""));
        assert!(!is_vault_envelope("v1:"));
        assert!(!is_vault_envelope("v1"));
        assert!(!is_vault_envelope("v:data"));
        assert!(!is_vault_envelope("v1data"));
        assert!(!is_vault_envelope("va:data"));
        assert!(!is_vault_envelope("plaintext"));
        assert!(!is_vault_envelope("abc"));
        // Fresh TOTP base32 must never look like an envelope (issue #11).
        assert!(!is_vault_envelope("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn test_vault_envelope_version() {
        assert_eq!(vault_envelope_version("v12:x"), Some(12));
        assert_eq!(vault_envelope_version("v1:AAAA"), Some(1));
        assert_eq!(vault_envelope_version("v999:long"), Some(999));
        assert_eq!(vault_envelope_version("plaintext"), None);
        assert_eq!(vault_envelope_version("v1:"), None);
        assert_eq!(vault_envelope_version("va:data"), None);
    }

    /// Battle: concurrent classification on a fixed corpus yields identical
    /// results across threads (pure, race-free).
    #[test]
    fn battle_concurrent_classification_is_deterministic() {
        let corpus: Arc<Vec<(&str, bool)>> = Arc::new(vec![
            ("v1:data", true),
            ("v12:AAAA", true),
            ("v999:longdata", true),
            ("plaintext", false),
            ("", false),
            ("v1:", false),
            ("v:data", false),
            ("v1data", false),
            ("va:data", false),
            ("JBSWY3DPEHPK3PXP", false),
        ]);
        let n = 8usize;
        let barrier = Arc::new(Barrier::new(n));
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let corpus = Arc::clone(&corpus);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                corpus
                    .iter()
                    .map(|(s, expected)| (is_vault_envelope(s), *expected))
                    .collect::<Vec<_>>()
            }));
        }
        let mut results = Vec::with_capacity(n);
        for h in handles {
            results.push(h.join().expect("thread"));
        }
        let first = &results[0];
        for row in &results[1..] {
            assert_eq!(row, first);
        }
        for (got, expected) in first {
            assert_eq!(got, expected);
        }
    }
}
