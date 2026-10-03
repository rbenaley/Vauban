//! SPKI pin. The certificate being checked is not the trust anchor:
//! its subject public key is hashed and compared to a pin that arrived
//! out of band (hop 1, TOFU store, or the asset record).

use base64::Engine;
use sha2::{Digest, Sha256};
use x509_cert::der::{Decode, Encode};

/// `SHA256:<standard-base64>` of the certificate's SubjectPublicKeyInfo.
pub fn spki_sha256_fingerprint(cert_der: &[u8]) -> Result<String, String> {
    let parsed =
        x509_cert::Certificate::from_der(cert_der).map_err(|e| format!("certificate: {e}"))?;
    let spki = parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| format!("spki: {e}"))?;
    let digest = Sha256::digest(&spki);
    Ok(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    ))
}

/// Constant-time compare of two pins. Each side may be `SHA256:<b64>` or
/// the bare base64 body. A missing or empty pin refuses.
///
/// An attacker who swaps the certificate cannot pass this check: the
/// test `attack_tunnel_spki_mismatch_is_rejected` presents a different
/// digest and expects a refusal.
pub fn pins_match(expected: &str, presented: &str) -> bool {
    let Some(expected) = expected.strip_prefix("SHA256:").filter(|s| !s.is_empty()) else {
        return false;
    };
    let presented = presented.strip_prefix("SHA256:").unwrap_or(presented);
    if presented.is_empty() {
        return false;
    }
    if expected.len() != presented.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.bytes().zip(presented.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_tunnel_spki_mismatch_is_rejected() {
        assert!(!pins_match("SHA256:aaaa", "bbbb"));
        assert!(!pins_match("SHA256:aaaa", "SHA256:bbbb"));
        assert!(!pins_match("aaaa", "aaaa"));
        assert!(pins_match("SHA256:aaaa", "aaaa"));
        assert!(pins_match("SHA256:aaaa", "SHA256:aaaa"));
    }
}
