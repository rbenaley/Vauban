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
pub mod audit_authors;
pub mod auth;
pub mod broadcast;
pub mod broker_latency;
pub mod connections;
pub mod dashboard;
pub mod rate_limit;
pub mod rbac;
pub mod mailer;
pub mod recording_hydrator;
pub mod role_invariants;
pub mod session_access;
pub mod smtp_client;
pub mod system_health;
pub mod virtual_group;

pub use access::*;
pub use asset_membership::*;
pub use auth::*;
pub use broadcast::*;
pub use connections::*;
pub use rate_limit::*;
pub use rbac::*;
