//! AES-256-GCM encryption/decryption primitives.
//!
//! This module provides the low-level cryptographic operations for vauban-vault.
//! All nonces are generated from the OS random number generator (arc4random on FreeBSD).
//! Plaintext buffers are zeroized after use.

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use zeroize::Zeroize;

/// Nonce size for AES-256-GCM (96 bits / 12 bytes).
const NONCE_SIZE: usize = 12;

/// Encrypt plaintext with AES-256-GCM.
///
/// Returns `nonce || ciphertext || tag` as a single byte vector.
/// The nonce is randomly generated from `OsRng`.
pub fn encrypt(key: &Key<Aes256Gcm>, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Prepend nonce to ciphertext: nonce || ciphertext || tag
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data produced by [`encrypt`].
///
/// Expects `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
/// Returns the decrypted plaintext. The caller is responsible for
/// zeroizing the returned buffer when done.
pub fn decrypt(key: &Key<Aes256Gcm>, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < NONCE_SIZE + 16 {
        // Minimum: 12-byte nonce + 16-byte GCM tag (empty plaintext)
        return Err(CryptoError::InvalidCiphertext);
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new(key);
    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Return ownership; caller must zeroize
    let result = plaintext.clone();
    plaintext.zeroize();
    Ok(result)
}

/// Errors from cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed (wrong key or tampered data)")]
    DecryptionFailed,

    #[error("invalid ciphertext (too short)")]
    InvalidCiphertext,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a random AES-256 key for testing.
    fn test_key() -> Key<Aes256Gcm> {
        Aes256Gcm::generate_key(&mut OsRng)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"hello, vauban-vault!";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext_each_time() {
        let key = test_key();
        let plaintext = b"same plaintext";

        let enc1 = encrypt(&key, plaintext).unwrap();
        let enc2 = encrypt(&key, plaintext).unwrap();

        // Different nonces must produce different ciphertexts
        assert_ne!(enc1, enc2);

        // But both must decrypt to the same plaintext
        assert_eq!(decrypt(&key, &enc1).unwrap(), plaintext);
        assert_eq!(decrypt(&key, &enc2).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let key1 = test_key();
        let key2 = test_key();
        let plaintext = b"secret data";

        let encrypted = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &encrypted);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::DecryptionFailed));
    }

    #[test]
    fn test_decrypt_with_tampered_ciphertext_fails() {
        let key = test_key();
        let plaintext = b"integrity check";

        let mut encrypted = encrypt(&key, plaintext).unwrap();

        // Tamper with the ciphertext (after the nonce)
        let tamper_idx = NONCE_SIZE + 1;
        if tamper_idx < encrypted.len() {
            encrypted[tamper_idx] ^= 0xFF;
        }

        let result = decrypt(&key, &encrypted);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::DecryptionFailed));
    }

    #[test]
    fn test_decrypt_with_tampered_nonce_fails() {
        let key = test_key();
        let plaintext = b"nonce integrity";

        let mut encrypted = encrypt(&key, plaintext).unwrap();

        // Tamper with the nonce (first 12 bytes)
        encrypted[0] ^= 0xFF;

        let result = decrypt(&key, &encrypted);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::DecryptionFailed));
    }

    #[test]
    fn test_decrypt_too_short_data_fails() {
        let key = test_key();

        // Less than nonce (12) + tag (16) = 28 bytes minimum
        let result = decrypt(&key, &[0u8; 27]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidCiphertext));
    }

    #[test]
    fn test_decrypt_empty_data_fails() {
        let key = test_key();
        let result = decrypt(&key, &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidCiphertext));
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = test_key();
        let plaintext = b"";

        let encrypted = encrypt(&key, plaintext).unwrap();
        // nonce (12) + tag (16) = 28 bytes minimum
        assert_eq!(encrypted.len(), 28);

        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_large_plaintext() {
        let key = test_key();
        let plaintext = vec![0x42u8; 4096]; // 4 KB

        let encrypted = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_does_not_contain_plaintext() {
        let key = test_key();
        let plaintext = b"FINDME_IN_CIPHERTEXT";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let encrypted_str = String::from_utf8_lossy(&encrypted);

        assert!(
            !encrypted_str.contains("FINDME_IN_CIPHERTEXT"),
            "Ciphertext must not contain plaintext"
        );
    }
}
