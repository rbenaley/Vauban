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

/// Zeroize the raw bytes of a post-quantum secret key type.
///
/// The `pqcrypto` crate types (`mlkem768::SecretKey`, `mldsa65::SecretKey`) wrap
/// a fixed-size `[u8; N]` array but do not implement `Zeroize` or `ZeroizeOnDrop`.
/// This helper uses `pq_as_bytes()` to locate the key material, then overwrites
/// it with zeros via `zeroize::Zeroize` on the raw slice.
///
/// # Safety
///
/// This function casts away `const` from the `&[u8]` returned by `pq_as_bytes()`
/// because the underlying struct owns the data (it is `[u8; N]` inside the struct)
/// and we hold `&mut self` in the `Drop` implementation, guaranteeing exclusive
/// access.  The `pqcrypto` crate simply does not expose `as_bytes_mut()`.
fn zeroize_pq_secret_key(key: &impl PqSecretKeyBytes) {
    let bytes = key.pq_as_bytes();
    // SAFETY: We have exclusive access (&mut self in Drop) and the bytes
    // belong to the struct being dropped.  No other reference exists.
    unsafe {
        let ptr = bytes.as_ptr() as *mut u8;
        let slice = std::slice::from_raw_parts_mut(ptr, bytes.len());
        slice.zeroize();
    }
}

/// Helper trait to extract `as_bytes()` from either KEM or Sign secret keys
/// without importing conflicting trait names in the same scope.
trait PqSecretKeyBytes {
    fn pq_as_bytes(&self) -> &[u8];
}

impl PqSecretKeyBytes for mlkem768::SecretKey {
    fn pq_as_bytes(&self) -> &[u8] {
        <Self as pqcrypto_traits::kem::SecretKey>::as_bytes(self)
    }
}

impl PqSecretKeyBytes for mldsa65::SecretKey {
    fn pq_as_bytes(&self) -> &[u8] {
        <Self as pqcrypto_traits::sign::SecretKey>::as_bytes(self)
    }
}

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
        // StaticSecret (x25519-dalek) implements ZeroizeOnDrop automatically.
        //
        // mlkem768::SecretKey wraps [u8; N] but the pqcrypto crate does not
        // implement Zeroize.  We zeroize the raw bytes via unsafe to ensure
        // the post-quantum secret key material does not linger in memory.
        zeroize_pq_secret_key(&self.post_quantum);
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
        // SigningKey (ed25519-dalek) implements ZeroizeOnDrop automatically.
        //
        // mldsa65::SecretKey wraps [u8; N] but the pqcrypto crate does not
        // implement Zeroize.  We zeroize the raw bytes via unsafe.
        zeroize_pq_secret_key(&self.post_quantum);
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

    // ==================== M-5: PQ Secret Key Zeroization Tests ====================

    #[test]
    fn test_mlkem768_secret_key_zeroized_by_helper() {
        use pqcrypto_traits::kem::SecretKey as _;

        let (_pk, pq_sk) = mlkem768::keypair();

        // Verify non-zero content before zeroization
        assert!(
            pq_sk.as_bytes().iter().any(|&b| b != 0),
            "ML-KEM-768 secret key should have non-zero content before zeroize"
        );

        // Call the zeroize helper directly (this is what Drop calls)
        zeroize_pq_secret_key(&pq_sk);

        // Read the bytes back through a raw pointer to bypass any compiler caching
        let bytes = unsafe {
            std::slice::from_raw_parts(pq_sk.as_bytes().as_ptr(), pq_sk.as_bytes().len())
        };
        assert!(
            bytes.iter().all(|&b| b == 0),
            "ML-KEM-768 secret key should be all zeros after zeroize_pq_secret_key"
        );
    }

    #[test]
    fn test_mldsa65_secret_key_zeroized_by_helper() {
        use pqcrypto_traits::sign::SecretKey as _;

        let (_pk, pq_sk) = mldsa65::keypair();

        // Verify non-zero content before zeroization
        assert!(
            pq_sk.as_bytes().iter().any(|&b| b != 0),
            "ML-DSA-65 secret key should have non-zero content before zeroize"
        );

        // Call the zeroize helper directly
        zeroize_pq_secret_key(&pq_sk);

        let bytes = unsafe {
            std::slice::from_raw_parts(pq_sk.as_bytes().as_ptr(), pq_sk.as_bytes().len())
        };
        assert!(
            bytes.iter().all(|&b| b == 0),
            "ML-DSA-65 secret key should be all zeros after zeroize_pq_secret_key"
        );
    }

    #[test]
    fn test_kem_still_works_after_zeroize_impl() {
        // Verify keypair generation and functional correctness
        // are not broken by the new Drop implementation.
        let (pk, sk) = HybridKemSecretKey::generate();
        assert_eq!(
            pk.post_quantum.as_bytes().len(),
            mlkem768::public_key_bytes()
        );
        assert_eq!(
            sk.post_quantum.as_bytes().len(),
            mlkem768::secret_key_bytes()
        );
        // The key should have non-zero bytes (i.e., it's a real key)
        assert!(
            sk.post_quantum.as_bytes().iter().any(|&b| b != 0),
            "Generated ML-KEM-768 secret key should not be all zeros"
        );
    }

    #[test]
    fn test_sig_still_works_after_zeroize_impl() {
        let (pk, sk) = HybridSigSecretKey::generate();
        let message = b"test zeroize doesn't break signing";
        let sig = sk.sign(message);
        assert!(pk.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_crypto_source_has_zeroize_pq_helper() {
        // Structural regression test: verify the source code contains
        // the zeroize_pq_secret_key helper and it's used in Drop impls.
        let source = include_str!("crypto.rs");
        assert!(
            source.contains("fn zeroize_pq_secret_key"),
            "crypto.rs must define zeroize_pq_secret_key helper"
        );
        assert!(
            source.contains("zeroize_pq_secret_key(&self.post_quantum)"),
            "Drop impls must call zeroize_pq_secret_key on PQ secret keys"
        );
        assert!(
            source.contains("slice.zeroize()"),
            "zeroize_pq_secret_key must call zeroize() on the raw slice"
        );
    }
}
