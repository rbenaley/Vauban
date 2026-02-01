use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
/// VAUBAN Web - Post-Quantum Cryptography (PQC) module.
///
/// Implements hybrid cryptographic schemes combining classical algorithms
/// (X25519, Ed25519) with post-quantum resistant algorithms (ML-KEM, ML-DSA).
use hkdf::Hkdf;
use pqcrypto_mldsa::mldsa65;
use pqcrypto_mlkem::mlkem768;
use sha3::Sha3_256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Invalid key format")]
    InvalidKey,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("KEM encapsulation failed")]
    KemEncapsulationFailed,
    #[error("KEM decapsulation failed")]
    KemDecapsulationFailed,
}

pub type CryptoResult<T> = Result<T, CryptoError>;

// ==================== Hybrid KEM (X25519 + ML-KEM-768) ====================

/// Hybrid KEM public key.
pub struct HybridKemPublicKey {
    pub classical: X25519PublicKey,
    pub post_quantum: mlkem768::PublicKey,
}

/// Hybrid KEM secret key.
pub struct HybridKemSecretKey {
    pub classical: StaticSecret,
    pub post_quantum: mlkem768::SecretKey,
}

impl Drop for HybridKemSecretKey {
    fn drop(&mut self) {
        // StaticSecret implements ZeroizeOnDrop in 2.0
        // mlkem768::SecretKey does not support Zeroize currently
    }
}

impl HybridKemSecretKey {
    /// Generate a new hybrid keypair.
    pub fn generate() -> (HybridKemPublicKey, Self) {
        use rand::rngs::OsRng;

        let classical_secret = StaticSecret::random_from_rng(OsRng);
        let classical_public = X25519PublicKey::from(&classical_secret);

        let (pq_public, pq_secret) = mlkem768::keypair();

        (
            HybridKemPublicKey {
                classical: classical_public,
                post_quantum: pq_public,
            },
            Self {
                classical: classical_secret,
                post_quantum: pq_secret,
            },
        )
    }
}

/// Combine classical and post-quantum shared secrets using HKDF SHA3-256.
pub fn combine_shared_secrets(classical: &[u8], pq: &[u8]) -> CryptoResult<[u8; 32]> {
    let mut ikm = Vec::with_capacity(classical.len() + pq.len());
    ikm.extend_from_slice(classical);
    ikm.extend_from_slice(pq);

    let hkdf = Hkdf::<Sha3_256>::new(None, &ikm);
    let mut output = [0u8; 32];
    hkdf.expand(b"vauban-hybrid-kem-v1", &mut output)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    ikm.zeroize();
    Ok(output)
}

/// Constant-time comparison to prevent timing attacks.
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

// ==================== Hybrid Signature (Ed25519 + ML-DSA-65) ====================

/// Hybrid signature public key.
pub struct HybridSigPublicKey {
    pub classical: VerifyingKey,
    pub post_quantum: mldsa65::PublicKey,
}

/// Hybrid signature secret key.
pub struct HybridSigSecretKey {
    pub classical: SigningKey,
    pub post_quantum: mldsa65::SecretKey,
}

impl Drop for HybridSigSecretKey {
    fn drop(&mut self) {
        // SigningKey implements ZeroizeOnDrop
    }
}

/// Combined hybrid signature.
pub struct HybridSignature {
    pub classical: Ed25519Signature,
    pub post_quantum: mldsa65::DetachedSignature,
}

impl HybridSigSecretKey {
    /// Generate a new hybrid signature keypair.
    pub fn generate() -> (HybridSigPublicKey, Self) {
        use rand::rngs::OsRng;

        let mut ed25519_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut ed25519_bytes);
        let classical_secret = SigningKey::from_bytes(&ed25519_bytes);
        let classical_public = classical_secret.verifying_key();

        let (pq_public, pq_secret) = mldsa65::keypair();

        (
            HybridSigPublicKey {
                classical: classical_public,
                post_quantum: pq_public,
            },
            Self {
                classical: classical_secret,
                post_quantum: pq_secret,
            },
        )
    }

    /// Sign a message using both algorithms.
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let classical_sig = self.classical.sign(message);
        let pq_sig = mldsa65::detached_sign(message, &self.post_quantum);

        HybridSignature {
            classical: classical_sig,
            post_quantum: pq_sig,
        }
    }
}

impl HybridSigPublicKey {
    /// Verify a hybrid signature.
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> CryptoResult<()> {
        // Verify classical signature
        self.classical
            .verify(message, &signature.classical)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        // Verify post-quantum signature
        mldsa65::verify_detached_signature(&signature.post_quantum, message, &self.post_quantum)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};

    #[test]
    fn test_hybrid_kem_keypair_generation() {
        let (pk, sk) = HybridKemSecretKey::generate();
        assert_eq!(
            pk.post_quantum.as_bytes().len(),
            mlkem768::public_key_bytes()
        );
        assert_eq!(
            sk.post_quantum.as_bytes().len(),
            mlkem768::secret_key_bytes()
        );
    }

    #[test]
    fn test_combine_shared_secrets() {
        let classical = [1u8; 32];
        let pq = [2u8; 32];
        let combined = unwrap_ok!(combine_shared_secrets(&classical, &pq));
        assert_ne!(combined, [0u8; 32]);

        let combined2 = unwrap_ok!(combine_shared_secrets(&classical, &pq));
        assert_eq!(combined, combined2);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = [1, 2, 3];
        let b = [1, 2, 3];
        let c = [1, 2, 4];
        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
    }

    #[test]
    fn test_hybrid_signature_flow() {
        let (pk, sk) = HybridSigSecretKey::generate();
        let message = b"Hello, Vauban Secure World!";

        let sig = sk.sign(message);
        assert!(pk.verify(message, &sig).is_ok());

        let wrong_message = b"Something else";
        assert!(pk.verify(wrong_message, &sig).is_err());
    }
}
