/// VAUBAN Web - Post-Quantum Cryptography (PQC) module.
///
/// Implements hybrid cryptographic schemes combining classical algorithms
/// (X25519, Ed25519) with post-quantum resistant algorithms (ML-KEM, ML-DSA)
/// via the RustCrypto `ml-kem` / `ml-dsa` crates.
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey,
    Verifier as Ed25519Verifier, VerifyingKey,
};
use hkdf::Hkdf;
use ml_dsa::{
    Generate as MlDsaGenerate, KeyExport as MlDsaKeyExport, Keypair as MlDsaKeypair, MlDsa65,
    Signature as MlDsaSignature, SignatureEncoding, Signer as MlDsaSigner,
    SigningKey as MlDsaSigningKey, Verifier as MlDsaVerifier, VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::kem::Kem;
use ml_kem::{
    Ciphertext as MlKemCiphertext, Decapsulate, DecapsulationKey768, Encapsulate,
    EncapsulationKey768, MlKem768,
};
use sha3::Sha3_256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// FIPS 203 ML-KEM-768 encapsulation-key size (bytes).
pub const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1184;
/// FIPS 203 ML-KEM-768 expanded decapsulation-key size (bytes).
pub const ML_KEM_768_SECRET_KEY_BYTES: usize = 2400;
/// FIPS 203 ML-KEM-768 seed size (preferred secret serialization).
pub const ML_KEM_768_SEED_BYTES: usize = 64;
/// FIPS 203 ML-KEM-768 ciphertext size (bytes).
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;
/// FIPS 204 ML-DSA-65 public-key size (bytes).
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
/// FIPS 204 ML-DSA-65 expanded secret-key size (bytes).
pub const ML_DSA_65_SECRET_KEY_BYTES: usize = 4032;
/// FIPS 204 ML-DSA-65 seed size (preferred secret serialization).
pub const ML_DSA_65_SEED_BYTES: usize = 32;
/// FIPS 204 ML-DSA-65 signature size (bytes).
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

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
    pub post_quantum: EncapsulationKey768,
}

/// Hybrid KEM secret key.
///
/// `ZeroizeOnDrop` covers both the X25519 `StaticSecret` and the ML-KEM-768
/// decapsulation key (RustCrypto `zeroize` feature). Raw pointer overwrite
/// of secret key bytes is not required.
#[derive(ZeroizeOnDrop)]
pub struct HybridKemSecretKey {
    pub classical: StaticSecret,
    pub post_quantum: DecapsulationKey768,
}

/// Hybrid KEM ciphertext: ephemeral X25519 public + ML-KEM-768 ciphertext.
pub struct HybridKemCiphertext {
    pub classical: X25519PublicKey,
    pub post_quantum: MlKemCiphertext<MlKem768>,
}

impl HybridKemSecretKey {
    /// Generate a new hybrid keypair.
    pub fn generate() -> (HybridKemPublicKey, Self) {
        use rand::rngs::OsRng;

        let classical_secret = StaticSecret::random_from_rng(OsRng);
        let classical_public = X25519PublicKey::from(&classical_secret);

        let (pq_secret, pq_public) = MlKem768::generate_keypair();

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

    /// Encoded ML-KEM-768 seed length (preferred secret serialization, 64 B).
    ///
    /// The FIPS 203 expanded decapsulation key is
    /// [`ML_KEM_768_SECRET_KEY_BYTES`]; RustCrypto serializes the seed.
    pub fn pq_secret_key_len(&self) -> usize {
        self.post_quantum.to_bytes().len()
    }

    /// Decapsulate a hybrid ciphertext and HKDF-combine with X25519 DH.
    pub fn decapsulate(&self, ciphertext: &HybridKemCiphertext) -> CryptoResult<[u8; 32]> {
        if ciphertext.pq_ciphertext_len() != ML_KEM_768_CIPHERTEXT_BYTES {
            return Err(CryptoError::KemDecapsulationFailed);
        }
        let classical_shared = self.classical.diffie_hellman(&ciphertext.classical);
        let pq_shared = self.post_quantum.decapsulate(&ciphertext.post_quantum);
        combine_shared_secrets(classical_shared.as_bytes(), pq_shared.as_slice())
    }
}

impl HybridKemPublicKey {
    /// Encoded ML-KEM-768 encapsulation-key length (FIPS 203).
    pub fn pq_public_key_len(&self) -> usize {
        self.post_quantum.to_bytes().len()
    }

    /// Encapsulate a hybrid shared secret to this public key.
    ///
    /// Combines an ephemeral X25519 Diffie-Hellman share with ML-KEM-768
    /// encapsulation, then HKDF-SHA3-256 (`vauban-hybrid-kem-v1`).
    pub fn encapsulate(&self) -> CryptoResult<([u8; 32], HybridKemCiphertext)> {
        use rand::rngs::OsRng;

        let eph = StaticSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph);
        let classical_shared = eph.diffie_hellman(&self.classical);

        let (pq_ct, pq_shared) = self.post_quantum.encapsulate();
        if pq_ct.len() != ML_KEM_768_CIPHERTEXT_BYTES {
            return Err(CryptoError::KemEncapsulationFailed);
        }

        let hybrid = combine_shared_secrets(classical_shared.as_bytes(), pq_shared.as_slice())?;
        Ok((
            hybrid,
            HybridKemCiphertext {
                classical: eph_pub,
                post_quantum: pq_ct,
            },
        ))
    }
}

impl HybridKemCiphertext {
    /// Encoded ML-KEM-768 ciphertext length (FIPS 203).
    pub fn pq_ciphertext_len(&self) -> usize {
        self.post_quantum.len()
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

/// Constant-time comparison to prevent timing attacks (bytes).
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Constant-time string comparison to prevent timing attacks.
///
/// Canonical implementation used by CSRF, flash cookie, and API key validation.
/// Delegates to the byte-level `constant_time_compare` for consistent behavior.
pub fn constant_time_compare_str(a: &str, b: &str) -> bool {
    constant_time_compare(a.as_bytes(), b.as_bytes())
}

// ==================== Hybrid Signature (Ed25519 + ML-DSA-65) ====================

/// Hybrid signature public key.
pub struct HybridSigPublicKey {
    pub classical: VerifyingKey,
    pub post_quantum: MlDsaVerifyingKey<MlDsa65>,
}

/// Hybrid signature secret key.
#[derive(ZeroizeOnDrop)]
pub struct HybridSigSecretKey {
    pub classical: SigningKey,
    pub post_quantum: MlDsaSigningKey<MlDsa65>,
}

/// Combined hybrid signature.
pub struct HybridSignature {
    pub classical: Ed25519Signature,
    pub post_quantum: MlDsaSignature<MlDsa65>,
}

impl HybridSigSecretKey {
    /// Generate a new hybrid signature keypair.
    pub fn generate() -> (HybridSigPublicKey, Self) {
        use rand::rngs::OsRng;

        let classical_secret = SigningKey::generate(&mut OsRng);
        let classical_public = classical_secret.verifying_key();

        let pq_secret = MlDsaSigningKey::<MlDsa65>::generate();

        (
            HybridSigPublicKey {
                classical: classical_public,
                post_quantum: pq_secret.verifying_key().clone(),
            },
            Self {
                classical: classical_secret,
                post_quantum: pq_secret,
            },
        )
    }

    /// Encoded ML-DSA-65 signing-key length (seed or expanded, via `KeyExport`).
    pub fn pq_secret_key_len(&self) -> usize {
        self.post_quantum.to_bytes().len()
    }

    /// Sign a message using both algorithms.
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let classical_sig = Ed25519Signer::sign(&self.classical, message);
        let pq_sig = MlDsaSigner::sign(&self.post_quantum, message);

        HybridSignature {
            classical: classical_sig,
            post_quantum: pq_sig,
        }
    }
}

impl HybridSigPublicKey {
    /// Encoded ML-DSA-65 verifying-key length (FIPS 204).
    pub fn pq_public_key_len(&self) -> usize {
        self.post_quantum.to_bytes().len()
    }

    /// Verify a hybrid signature. Both halves must succeed.
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> CryptoResult<()> {
        self.classical
            .verify(message, &signature.classical)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        self.post_quantum
            .verify(message, &signature.post_quantum)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        Ok(())
    }
}

impl HybridSignature {
    /// Encoded ML-DSA-65 signature length (FIPS 204).
    pub fn pq_signature_len(&self) -> usize {
        self.post_quantum.to_bytes().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_keypair_generation() {
        let (pk, sk) = HybridKemSecretKey::generate();
        assert_eq!(pk.pq_public_key_len(), ML_KEM_768_PUBLIC_KEY_BYTES);
        assert_eq!(sk.pq_secret_key_len(), ML_KEM_768_SEED_BYTES);
        assert_eq!(ML_KEM_768_SECRET_KEY_BYTES, 2400);
    }

    #[test]
    fn test_hybrid_kem_encapsulate_decapsulate_same_secret() {
        let (pk, sk) = HybridKemSecretKey::generate();
        let (send, ct) = unwrap_ok!(pk.encapsulate());
        let recv = unwrap_ok!(sk.decapsulate(&ct));
        assert_eq!(send, recv);
        assert_ne!(send, [0u8; 32]);
        assert_eq!(ct.pq_ciphertext_len(), ML_KEM_768_CIPHERTEXT_BYTES);
    }

    #[test]
    fn attack_hybrid_kem_foreign_decapsulate_does_not_match() {
        let (pk, _sk) = HybridKemSecretKey::generate();
        let (_pk_other, sk_other) = HybridKemSecretKey::generate();
        let (send, ct) = unwrap_ok!(pk.encapsulate());
        let foreign = unwrap_ok!(sk_other.decapsulate(&ct));
        assert_ne!(send, foreign);
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
    fn test_combine_shared_secrets_differs_on_ikm_change() {
        let a = unwrap_ok!(combine_shared_secrets(&[1u8; 32], &[2u8; 32]));
        let b = unwrap_ok!(combine_shared_secrets(&[1u8; 32], &[3u8; 32]));
        assert_ne!(a, b);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = [1, 2, 3];
        let b = [1, 2, 3];
        let c = [1, 2, 4];
        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
        assert!(!constant_time_compare(&a, &[1, 2]));
    }

    #[test]
    fn test_constant_time_compare_str() {
        assert!(constant_time_compare_str("csrf", "csrf"));
        assert!(!constant_time_compare_str("csrf", "CSRF"));
        assert!(!constant_time_compare_str("csrf", "csr"));
    }

    #[test]
    fn test_hybrid_signature_flow() {
        let (pk, sk) = HybridSigSecretKey::generate();
        let message = b"Hello, Vauban Secure World!";

        let sig = sk.sign(message);
        assert!(pk.verify(message, &sig).is_ok());
        assert_eq!(pk.pq_public_key_len(), ML_DSA_65_PUBLIC_KEY_BYTES);
        assert_eq!(sig.pq_signature_len(), ML_DSA_65_SIGNATURE_BYTES);
        let sk_len = sk.pq_secret_key_len();
        assert!(
            sk_len == ML_DSA_65_SECRET_KEY_BYTES || sk_len == ML_DSA_65_SEED_BYTES,
            "ML-DSA-65 secret encoding must be FIPS expanded ({ML_DSA_65_SECRET_KEY_BYTES}) or seed ({ML_DSA_65_SEED_BYTES}), got {sk_len}"
        );
    }

    #[test]
    fn forged_hybrid_signature_is_rejected() {
        let (_pk_a, sk_a) = HybridSigSecretKey::generate();
        let (pk_b, _sk_b) = HybridSigSecretKey::generate();
        let sig = sk_a.sign(b"payload");
        assert!(pk_b.verify(b"payload", &sig).is_err());
    }

    #[test]
    fn forged_hybrid_signature_wrong_message_is_rejected() {
        let (pk, sk) = HybridSigSecretKey::generate();
        let sig = sk.sign(b"Hello, Vauban Secure World!");
        assert!(pk.verify(b"Something else", &sig).is_err());
    }

    #[test]
    fn forged_hybrid_signature_tampered_classical_is_rejected() {
        let (pk, sk) = HybridSigSecretKey::generate();
        let mut sig = sk.sign(b"payload");
        let mut bytes = sig.classical.to_bytes();
        bytes[0] ^= 0xff;
        sig.classical = Ed25519Signature::from_bytes(&bytes);
        assert!(pk.verify(b"payload", &sig).is_err());
    }

    #[test]
    fn forged_hybrid_signature_tampered_post_quantum_is_rejected() {
        let (pk, sk) = HybridSigSecretKey::generate();
        let mut sig = sk.sign(b"payload");
        let mut bytes = sig.post_quantum.to_bytes();
        bytes[0] ^= 0xff;
        sig.post_quantum = unwrap_ok!(MlDsaSignature::<MlDsa65>::try_from(bytes.as_slice()));
        assert!(pk.verify(b"payload", &sig).is_err());
    }

    #[test]
    fn test_kem_still_works_with_zeroize_on_drop() {
        let (pk, sk) = HybridKemSecretKey::generate();
        let (send, ct) = unwrap_ok!(pk.encapsulate());
        let recv = unwrap_ok!(sk.decapsulate(&ct));
        assert_eq!(send, recv);
        assert_eq!(sk.pq_secret_key_len(), ML_KEM_768_SEED_BYTES);
    }

    #[test]
    fn test_sig_still_works_with_zeroize_on_drop() {
        let (pk, sk) = HybridSigSecretKey::generate();
        let message = b"test zeroize doesn't break signing";
        let sig = sk.sign(message);
        assert!(pk.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_crypto_source_uses_rustcrypto_zeroize_on_drop() {
        let source = include_str!("crypto.rs");
        let prod = source
            .split("#[cfg(test)]")
            .next()
            .expect("production half");
        assert!(
            !prod.contains("pqcrypto"),
            "crypto.rs production half must not import pqcrypto"
        );
        assert!(
            !prod.contains("zeroize_pq_secret_key"),
            "legacy unsafe zeroize helper must be gone"
        );
        assert!(
            !prod.contains("unsafe {") && !prod.contains("unsafe fn") && !prod.contains("as *mut"),
            "crypto.rs must not use an unsafe block after the RustCrypto swap"
        );
        assert!(
            source.contains("#[derive(ZeroizeOnDrop)]"),
            "hybrid secret keys must derive ZeroizeOnDrop"
        );
        assert!(
            source.contains("vauban-hybrid-kem-v1"),
            "HKDF label must stay vauban-hybrid-kem-v1"
        );
    }
}
