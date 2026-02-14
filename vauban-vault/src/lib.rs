//! Vauban Vault Library
//!
//! Exposes the cryptographic primitives and keyring management used by the
//! vauban-vault service. This library is also consumed by `vauban-migrate`
//! for batch secret migration.
//!
//! Re-exported modules:
//! - `crypto`: AES-256-GCM encrypt/decrypt primitives
//! - `keyring`: HKDF-SHA3-256 key derivation and versioned keyring

// L-1: Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic
#![cfg_attr(test, allow(
    clippy::unwrap_used, clippy::expect_used, clippy::panic,
    clippy::print_stdout, clippy::print_stderr
))]

pub mod crypto;
pub mod keyring;
