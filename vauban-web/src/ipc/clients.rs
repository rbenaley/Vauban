/// VAUBAN Web - IPC clients for communicating with Vauban services.
///
/// These clients use Unix pipes for inter-process communication with
/// the privilege-separated Vauban services (auth, rbac, vault, audit).
use std::time::Duration;
use tracing::warn;
#[cfg(not(debug_assertions))]
use tracing::error;

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

/// RBAC service client.
///
/// Communicates with vauban-rbac via Unix pipe.
pub struct RbacClient {
    #[allow(dead_code)]
    client: IpcClient,
}

impl RbacClient {
    pub async fn new(_config: &Config) -> AppResult<Self> {
        // In production, IPC channels are passed by the supervisor
        Ok(Self {
            client: IpcClient::new(),
        })
    }

    /// Check permission.
    ///
    /// TODO: Implement actual IPC communication with vauban-rbac.
    ///
    /// Security: the stub allow-all is only compiled in debug builds.
    /// In release builds, all requests are denied by default until the
    /// IPC communication with vauban-rbac is implemented.
    pub async fn check_permission(
        &self,
        _user_id: &str,
        _resource: &str,
        _action: &str,
    ) -> AppResult<bool> {
        #[cfg(debug_assertions)]
        {
            warn!("RBAC stub: allowing (debug build). NOT safe for production.");
            Ok(true)
        }
        #[cfg(not(debug_assertions))]
        {
            error!("RBAC IPC not implemented - denying by default");
            Ok(false)
        }
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

    // ==================== H-8 Regression Tests ====================

    /// Verify that in debug builds, the RBAC client stub allows all
    /// requests. This test documents the intentional debug behavior.
    /// In release builds (cargo test --release), the stub denies by default.
    #[tokio::test]
    #[cfg(debug_assertions)]
    async fn test_rbac_client_allows_in_debug_build() {
        let client = RbacClient {
            client: IpcClient::new(),
        };

        let result = client
            .check_permission("user:alice", "asset:server1", "ssh")
            .await;

        assert!(
            result.is_ok(),
            "RBAC client check_permission must not error in debug builds"
        );
        assert!(
            result.unwrap(),
            "RBAC client stub must return true (allow) in debug builds"
        );
    }

    /// Structural regression test: verify that the RBAC client source code
    /// contains cfg(debug_assertions) guards around the allow-all stub.
    #[test]
    fn test_rbac_client_has_cfg_debug_guard() {
        let source = include_str!("clients.rs");

        assert!(
            source.contains("#[cfg(debug_assertions)]"),
            "ipc/clients.rs must contain #[cfg(debug_assertions)] \
             to guard the RBAC allow-all stub"
        );
        assert!(
            source.contains("#[cfg(not(debug_assertions))]"),
            "ipc/clients.rs must contain #[cfg(not(debug_assertions))] \
             with a deny-by-default fallback"
        );
        assert!(
            source.contains("Ok(false)"),
            "ipc/clients.rs must contain a deny-by-default path \
             (Ok(false)) for release builds"
        );
    }
}
