//! VAUBAN Web - Services module.
//!
//! SECURITY: a `vault` submodule used to live here exposing a `VaultService`
//! whose `list_credentials` silently returned an empty `Vec`. It was dead
//! code (no caller ever instantiated `VaultService`), and the underlying
//! `ipc::clients::VaultClient` it wrapped has also been removed. Any future
//! credential-listing logic must go through encrypted-transit verbs in
//! [`crate::ipc::vault::VaultCryptoClient`].
pub mod access;
pub mod anomalies;
pub mod asset_membership;
pub mod audit;
pub mod audit_authors;
pub mod auth;
pub mod broadcast;
pub mod broker_latency;
pub mod connections;
pub mod dashboard;
pub mod iacs;
pub mod iacs_packet_analyzer;
pub mod iacs_tunnel;
pub mod mailer;
pub mod pending_mfa;
pub mod rate_limit;
pub mod rbac;
pub mod recording_hydrator;
pub mod recording_reaper;
pub mod role_invariants;
pub mod secret_access;
pub mod session_access;
pub mod session_activity;
pub mod session_limits;
pub mod session_revocation;
pub mod session_termination;
pub mod smtp_client;
pub mod system_health;
pub mod virtual_group;

pub use access::*;
pub use asset_membership::*;
pub use audit::{emit_audit, emit_audit_critical};
pub use auth::*;
pub use broadcast::*;
pub use connections::*;
pub use rate_limit::*;
pub use rbac::*;
