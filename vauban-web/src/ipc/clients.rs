//! VAUBAN Web - IPC clients for communicating with Vauban services.
//!
//! These clients use Unix pipes for inter-process communication with
//! the privilege-separated Vauban services (auth, access, vault, audit).
//!
//! The canonical Casbin-backed RBAC client is
//! [`crate::ipc::AccessIpcClient`] and its presence is mandatory at
//! vauban-web startup (see `init_access_client`).
//!
//! SECURITY: a `VaultClient` lived here that exposed an async
//! `list_credentials(...) -> Ok(vec![])` placeholder. It was removed in the
//! post-MFA security pass: a future caller could have interpreted the empty
//! list as "no credential exists for this asset" and silently bypassed
//! credential checks. Vault traffic must go through the encrypted-transit
//! verbs in [`crate::ipc::vault::VaultCryptoClient`].

use std::time::Duration;

/// IPC client placeholder for communicating with Vauban services.
///
/// In the privsep architecture, vauban-web communicates with other services
/// via Unix pipes created by the supervisor. Concrete clients
/// ([`crate::ipc::AccessIpcClient`], [`crate::ipc::AuthIpcClient`],
/// [`crate::ipc::VaultCryptoClient`], ...) wrap their own
/// [`shared::ipc::IpcChannel`]; this type only exists as a typed handle for
/// code paths that have not yet been wired to a concrete service and must
/// be replaced before they are used in production.
pub struct IpcClient {
    _placeholder: (),
}

impl IpcClient {
    /// Create a new IPC client placeholder.
    pub fn new() -> Self {
        Self { _placeholder: () }
    }
}

impl Default for IpcClient {
    fn default() -> Self {
        Self::new()
    }
}

/// IPC connection configuration helper.
#[derive(Debug, Clone)]
pub struct IpcConnectionConfig {
    pub service_name: String,
    pub timeout_secs: u64,
}

impl IpcConnectionConfig {
    /// Create a new IPC connection config.
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
            timeout_secs: 10,
        }
    }

    /// Set timeout.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Get timeout as Duration.
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_connection_config_new() {
        let config = IpcConnectionConfig::new("rbac");
        assert_eq!(config.service_name, "rbac");
        assert_eq!(config.timeout_secs, 10);
    }

    #[test]
    fn test_ipc_connection_config_with_timeout() {
        let config = IpcConnectionConfig::new("vault").with_timeout(30);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_ipc_connection_config_timeout_duration() {
        let config = IpcConnectionConfig::new("auth").with_timeout(15);
        assert_eq!(config.timeout(), Duration::from_secs(15));
    }

    #[test]
    fn test_ipc_client_new() {
        let client = IpcClient::new();
        // Just verify it can be created
        let _ = client;
    }

    #[test]
    fn test_ipc_client_default() {
        let client = IpcClient::default();
        let _ = client;
    }

    // ==================== Regression Tests ====================

    /// Structural non-regression: `clients.rs` must no longer contain the
    /// legacy allow-all RBAC stub. The canonical path goes through
    /// `AccessIpcClient` + Casbin.
    ///
    /// The forbidden patterns are reconstructed at runtime so they never
    /// appear literally in this file and cannot match against its own source.
    #[test]
    fn test_rbac_client_stub_has_been_removed() {
        let source = include_str!("clients.rs");

        let forbidden_struct = format!("pub {} Rbac{}", "struct", "Client");
        assert!(
            !source.contains(&forbidden_struct),
            "ipc/clients.rs must not define the legacy Rbac type (use AccessIpcClient + Casbin)"
        );

        let forbidden_cfg = format!("#[{}(debug_assertions)]", "cfg");
        assert!(
            !source.contains(&forbidden_cfg),
            "ipc/clients.rs must not carry debug-gated RBAC fallbacks"
        );
    }

    /// SECURITY: the legacy fail-open Vault placeholder client must not come
    /// back. Reconstruct the forbidden tokens at runtime so this test never
    /// matches against itself.
    #[test]
    fn test_silent_vault_placeholder_client_has_been_removed() {
        let source = include_str!("clients.rs");

        let forbidden_struct = format!("pub {} {}", "struct", "VaultClient");
        assert!(
            !source.contains(&forbidden_struct),
            "ipc/clients.rs must not redefine the legacy `VaultClient` placeholder \
             (it returned `Ok(vec![])` silently from `list_credentials` and was \
             removed for security; use VaultCryptoClient instead)"
        );

        let forbidden_fn = format!(
            "{} {}(",
            "async fn",
            "list_credentials"
        );
        assert!(
            !source.contains(&forbidden_fn),
            "ipc/clients.rs must not expose any `list_credentials` stub returning Ok(vec![])"
        );

        let forbidden_body = format!("{} {}", "Ok(", "vec![])");
        assert!(
            !source.contains(&forbidden_body),
            "ipc/clients.rs must not return an empty Vec silently from any IPC client"
        );
    }
}
