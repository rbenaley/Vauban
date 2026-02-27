//! ACME automatic certificate management for VAUBAN Web.
//!
//! This module provides a dynamic TLS resolver that supports:
//! - Normal HTTPS traffic with the production certificate
//! - TLS-ALPN-01 challenge certificates (ALPN `acme-tls/1`) for ACME validation
//! - Zero-downtime certificate rotation via in-memory activation
//!
//! The ACME protocol execution (account management, order creation, challenge
//! coordination, CSR finalization) is handled by `vauban-supervisor` using
//! `instant-acme`. This module only handles the TLS-side integration.

pub mod resolver;
