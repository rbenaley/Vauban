//! Versioned key derivation and keyring management.
//!
//! The keyring holds multiple versions of a domain-specific AES-256-GCM key,
//! all derived from the same master key via HKDF-SHA3-256 with distinct info
//! labels. New encryptions always use the latest version; decryption selects
//! the key version from the ciphertext prefix.

use aes_gcm::{Aes256Gcm, Key};
use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroize;

use crate::crypto;

/// 32-byte master key with automatic zeroization on drop.
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Read a 32-byte master key from a file.
    ///
    /// The file is opened, read exactly 32 bytes, and closed immediately.
    /// Call this BEFORE `cap_enter()`.
    pub fn from_file(path: &str) -> Result<Self, KeyError> {
        let data = std::fs::read(path).map_err(|e| KeyError::IoError(e.to_string()))?;
        if data.len() != 32 {
            return Err(KeyError::InvalidKeySize {
                expected: 32,
                got: data.len(),
            });
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        Ok(Self(key))
    }

    /// Create a master key from raw bytes.
    ///
    /// Used by tests and by `vauban-migrate` for programmatic key loading.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access the raw key material.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey([REDACTED])")
    }
}

/// Derive an AES-256-GCM key from the master key using HKDF-SHA3-256.
///
/// The info label encodes both the domain and version:
/// `"vauban-{domain}-v{version}"` (e.g. `"vauban-mfa-v1"`).
///
/// Properties:
/// - Deterministic: same master + domain + version = same derived key
/// - Domain-separated: different domains produce independent keys
/// - Version-separated: different versions produce independent keys
fn derive_key(master_key: &[u8; 32], domain: &str, version: u32) -> Key<Aes256Gcm> {
    let hkdf = Hkdf::<Sha3_256>::new(None, master_key);
    let info = format!("vauban-{}-v{}", domain, version);
    let mut derived = [0u8; 32];
    // HKDF expand to 32 bytes always succeeds (32 <= 255 * HashLen)
    hkdf.expand(info.as_bytes(), &mut derived)
        .expect("32 bytes is valid for HKDF-SHA3-256");
    let key = *Key::<Aes256Gcm>::from_slice(&derived);
    derived.zeroize();
    key
}

/// A versioned keyring for a single domain (e.g. "mfa" or "credentials").
///
/// Holds multiple derived keys, one per version. New encryptions use the
/// latest version; decryption selects the key matching the ciphertext's
/// version prefix.
pub struct Keyring {
    domain: String,
    /// (version, derived_key) sorted by version ascending.
    keys: Vec<(u32, Key<Aes256Gcm>)>,
    /// Current (latest) version number.
    current_version: u32,
}

impl Keyring {
    /// Build a new keyring for `domain` with keys derived from versions 1..=max_version.
    pub fn new(master_key: &[u8; 32], domain: &str, max_version: u32) -> Self {
        let mut keys = Vec::with_capacity(max_version as usize);
        for v in 1..=max_version {
            let key = derive_key(master_key, domain, v);
            keys.push((v, key));
        }
        Self {
            domain: domain.to_string(),
            keys,
            current_version: max_version,
        }
    }

    /// Encrypt plaintext with the latest key version.
    ///
    /// Returns a string in the format `"v{N}:{base64(nonce || ciphertext || tag)}"`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, KeyError> {
        let key = self.get_key(self.current_version)?;
        let encrypted = crypto::encrypt(key, plaintext)
            .map_err(|e| KeyError::CryptoError(e.to_string()))?;
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted);
        Ok(format!("v{}:{}", self.current_version, encoded))
    }

    /// Decrypt a versioned ciphertext string.
    ///
    /// Parses the `"v{N}:{base64}"` format, selects the matching key version,
    /// and decrypts. Returns the plaintext bytes.
    /// The caller must zeroize the returned buffer when done.
    pub fn decrypt(&self, ciphertext: &str) -> Result<Vec<u8>, KeyError> {
        let (version, data) = Self::parse_versioned_ciphertext(ciphertext)?;
        let key = self.get_key(version)?;
        crypto::decrypt(key, &data).map_err(|e| KeyError::CryptoError(e.to_string()))
    }

    /// Re-encrypt a ciphertext with the latest key version.
    ///
    /// Decrypts with the old key, encrypts with the current key.
    /// Used during key rotation (see Architecture doc Section 10.3).
    #[allow(dead_code)] // Will be used when key rotation is implemented
    pub fn rewrap(&self, ciphertext: &str) -> Result<String, KeyError> {
        let mut plaintext = self.decrypt(ciphertext)?;
        let result = self.encrypt(&plaintext);
        plaintext.zeroize();
        result
    }

    /// Return the domain name.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Return the current (latest) version.
    pub fn current_version(&self) -> u32 {
        self.current_version
    }

    /// Look up a key by version number.
    fn get_key(&self, version: u32) -> Result<&Key<Aes256Gcm>, KeyError> {
        self.keys
            .iter()
            .find(|(v, _)| *v == version)
            .map(|(_, k)| k)
            .ok_or(KeyError::UnknownVersion {
                version,
                domain: self.domain.clone(),
            })
    }

    /// Parse `"v{N}:{base64}"` into `(version, raw_bytes)`.
    fn parse_versioned_ciphertext(ciphertext: &str) -> Result<(u32, Vec<u8>), KeyError> {
        // Must start with 'v'
        if !ciphertext.starts_with('v') {
            return Err(KeyError::InvalidFormat(
                "ciphertext must start with 'v'".to_string(),
            ));
        }

        // Find the ':' separator
        let colon_pos = ciphertext
            .find(':')
            .ok_or_else(|| KeyError::InvalidFormat("missing ':' separator".to_string()))?;

        // Parse the version number between 'v' and ':'
        let version_str = &ciphertext[1..colon_pos];
        let version: u32 = version_str.parse().map_err(|_| {
            KeyError::InvalidFormat(format!("invalid version number: '{}'", version_str))
        })?;

        // Decode the base64 payload after ':'
        let b64_payload = &ciphertext[colon_pos + 1..];
        let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64_payload)
            .map_err(|e| KeyError::InvalidFormat(format!("invalid base64: {}", e)))?;

        Ok((version, data))
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        for (_, key) in &mut self.keys {
            key.as_mut_slice().zeroize();
        }
    }
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("domain", &self.domain)
            .field("current_version", &self.current_version)
            .field("key_count", &self.keys.len())
            .finish()
    }
}

/// Errors from key management operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("I/O error: {0}")]
    IoError(String),

    #[error("invalid key size: expected {expected} bytes, got {got}")]
    InvalidKeySize { expected: usize, got: usize },

    #[error("unknown key version {version} for domain '{domain}'")]
    UnknownVersion { version: u32, domain: String },

    #[error("invalid ciphertext format: {0}")]
    InvalidFormat(String),

    #[error("crypto error: {0}")]
    CryptoError(String),
}

/// Check whether a value looks like an encrypted ciphertext from vauban-vault.
///
/// Encrypted values have the format `"v{digit(s)}:{base64}"`.
/// This function does NOT validate the base64 payload or attempt decryption.
/// Also duplicated in `vauban-web/src/handlers/web.rs` for use at the web layer.
#[allow(dead_code)] // Used in tests; web layer has its own copy
pub fn is_encrypted(value: &str) -> bool {
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
    value[1..colon_pos].chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master_key() -> MasterKey {
        MasterKey::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ])
    }

    #[test]
    fn test_derive_key_is_deterministic() {
        let mk = test_master_key();
        let k1 = derive_key(mk.as_bytes(), "mfa", 1);
        let k2 = derive_key(mk.as_bytes(), "mfa", 1);
        assert_eq!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn test_different_domains_produce_different_keys() {
        let mk = test_master_key();
        let k1 = derive_key(mk.as_bytes(), "mfa", 1);
        let k2 = derive_key(mk.as_bytes(), "credentials", 1);
        assert_ne!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn test_different_versions_produce_different_keys() {
        let mk = test_master_key();
        let k1 = derive_key(mk.as_bytes(), "mfa", 1);
        let k2 = derive_key(mk.as_bytes(), "mfa", 2);
        assert_ne!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn test_keyring_encrypt_decrypt_roundtrip() {
        let mk = test_master_key();
        let kr = Keyring::new(mk.as_bytes(), "credentials", 1);

        let plaintext = b"my-ssh-password";
        let ciphertext = kr.encrypt(plaintext).unwrap();
        let decrypted = kr.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_keyring_encrypt_uses_latest_version() {
        let mk = test_master_key();
        let kr = Keyring::new(mk.as_bytes(), "mfa", 3);

        let ciphertext = kr.encrypt(b"secret").unwrap();
        assert!(ciphertext.starts_with("v3:"), "Should use version 3, got: {}", ciphertext);
    }

    #[test]
    fn test_keyring_decrypt_with_old_version_succeeds() {
        let mk = test_master_key();

        // Encrypt with version 1
        let kr_v1 = Keyring::new(mk.as_bytes(), "mfa", 1);
        let ciphertext = kr_v1.encrypt(b"old-secret").unwrap();
        assert!(ciphertext.starts_with("v1:"));

        // Decrypt with keyring that has versions 1, 2, 3
        let kr_v3 = Keyring::new(mk.as_bytes(), "mfa", 3);
        let decrypted = kr_v3.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, b"old-secret");
    }

    #[test]
    fn test_keyring_decrypt_with_unknown_version_fails() {
        let mk = test_master_key();
        let kr = Keyring::new(mk.as_bytes(), "mfa", 2);

        // Manually construct a v5:... ciphertext
        let result = kr.decrypt("v5:AAAA");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, KeyError::UnknownVersion { version: 5, .. }));
    }

    #[test]
    fn test_keyring_rewrap_upgrades_version() {
        let mk = test_master_key();

        // Encrypt with v1
        let kr_v1 = Keyring::new(mk.as_bytes(), "credentials", 1);
        let old_ciphertext = kr_v1.encrypt(b"rewrap-me").unwrap();
        assert!(old_ciphertext.starts_with("v1:"));

        // Rewrap with v3
        let kr_v3 = Keyring::new(mk.as_bytes(), "credentials", 3);
        let new_ciphertext = kr_v3.rewrap(&old_ciphertext).unwrap();
        assert!(new_ciphertext.starts_with("v3:"));

        // Verify plaintext is preserved
        let decrypted = kr_v3.decrypt(&new_ciphertext).unwrap();
        assert_eq!(decrypted, b"rewrap-me");
    }

    #[test]
    fn test_keyring_decrypt_invalid_format_no_prefix() {
        let mk = test_master_key();
        let kr = Keyring::new(mk.as_bytes(), "mfa", 1);
        let result = kr.decrypt("not-encrypted");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyError::InvalidFormat(_)));
    }

    #[test]
    fn test_keyring_decrypt_invalid_format_no_colon() {
        let mk = test_master_key();
        let kr = Keyring::new(mk.as_bytes(), "mfa", 1);
        let result = kr.decrypt("v1data");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyError::InvalidFormat(_)));
    }

    #[test]
    fn test_keyring_decrypt_invalid_base64() {
        let mk = test_master_key();
        let kr = Keyring::new(mk.as_bytes(), "mfa", 1);
        let result = kr.decrypt("v1:not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_keyring_ciphertext_fits_in_varchar_255() {
        let mk = test_master_key();
        let kr = Keyring::new(mk.as_bytes(), "mfa", 1);

        // TOTP secret is typically 32 chars base32
        let plaintext = b"JBSWY3DPEHPK3PXP";
        let ciphertext = kr.encrypt(plaintext).unwrap();
        assert!(
            ciphertext.len() < 255,
            "Ciphertext ({} chars) must fit in VARCHAR(255)",
            ciphertext.len()
        );
    }

    #[test]
    fn test_keyring_debug_does_not_leak_keys() {
        let mk = test_master_key();
        let kr = Keyring::new(mk.as_bytes(), "mfa", 2);
        let debug = format!("{:?}", kr);
        assert!(debug.contains("mfa"));
        assert!(debug.contains("current_version: 2"));
        assert!(debug.contains("key_count: 2"));
        // Must not contain raw key bytes
        assert!(!debug.contains("0x"));
    }

    #[test]
    fn test_master_key_debug_is_redacted() {
        let mk = test_master_key();
        let debug = format!("{:?}", mk);
        assert_eq!(debug, "MasterKey([REDACTED])");
    }

    #[test]
    fn test_is_encrypted_valid() {
        assert!(is_encrypted("v1:SGVsbG8="));
        assert!(is_encrypted("v12:AAAA"));
        assert!(is_encrypted("v999:data"));
    }

    #[test]
    fn test_is_encrypted_invalid() {
        assert!(!is_encrypted("plaintext"));
        assert!(!is_encrypted(""));
        assert!(!is_encrypted("v:data")); // no version number
        assert!(!is_encrypted("v1data")); // no colon
        assert!(!is_encrypted("va:data")); // non-digit version
        assert!(!is_encrypted("abc")); // too short
    }

    #[test]
    fn test_is_encrypted_distinguishes_plaintext_vs_ciphertext() {
        let mk = test_master_key();
        let kr = Keyring::new(mk.as_bytes(), "mfa", 1);

        // Plaintext TOTP secret (base32)
        assert!(!is_encrypted("JBSWY3DPEHPK3PXP"));

        // Encrypted TOTP secret
        let encrypted = kr.encrypt(b"JBSWY3DPEHPK3PXP").unwrap();
        assert!(is_encrypted(&encrypted));
    }

    #[test]
    fn test_keyring_different_domains_cannot_cross_decrypt() {
        let mk = test_master_key();
        let kr_mfa = Keyring::new(mk.as_bytes(), "mfa", 1);
        let kr_cred = Keyring::new(mk.as_bytes(), "credentials", 1);

        let ciphertext = kr_mfa.encrypt(b"mfa-secret").unwrap();

        // Same version prefix (v1:) but different domain -> different key -> decryption fails
        let result = kr_cred.decrypt(&ciphertext);
        assert!(result.is_err());
    }
}
