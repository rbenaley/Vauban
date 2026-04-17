/// VAUBAN Web - IPC clients for communicating with Vauban services.
///
/// These clients use Unix pipes for inter-process communication with
/// the privilege-separated Vauban services (auth, rbac, vault, audit).
///
/// The canonical Casbin-backed RBAC client is
/// [`crate::ipc::AccessIpcClient`] and its presence is mandatory at
/// vauban-web startup (see `init_access_client`).
use std::time::Duration;
use tracing::warn;

use crate::config::Config;
use crate::error::AppResult;

/// IPC client for communicating with Vauban services.
///
/// In the privsep architecture, vauban-web communicates with other services
/// (auth, rbac, audit) via Unix pipes created by the supervisor.
pub struct IpcClient {
    // TODO: IPC channel file descriptors will be passed by the supervisor
    _placeholder: (),
}

impl IpcClient {
    /// Create a new IPC client.
    ///
    /// In production, the file descriptors are passed by the supervisor.
    /// For now, this is a placeholder that allows the code to compile.
    pub fn new() -> Self {
        Self { _placeholder: () }
    }
}

impl Default for IpcClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Vault service client.
///
/// Communicates with vauban-vault via Unix pipe.
pub struct VaultClient {
    #[allow(dead_code)]
    client: IpcClient,
}

impl VaultClient {
    pub async fn new(_config: &Config) -> AppResult<Self> {
        // In production, IPC channels are passed by the supervisor
        Ok(Self {
            client: IpcClient::new(),
        })
    }

    /// List credentials.
    ///
    /// TODO: Implement actual IPC communication with vauban-vault.
    pub async fn list_credentials(&self, _asset_id: Option<&str>) -> AppResult<Vec<String>> {
        // TODO: Send VaultGetCredential message via IPC pipe
        warn!("Vault list_credentials called but IPC not yet implemented");
        Ok(vec![])
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
}
