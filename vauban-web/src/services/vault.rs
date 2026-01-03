/// VAUBAN Web - Vault service client wrapper.

use crate::config::Config;
use crate::error::AppResult;
use crate::grpc::VaultClient;

/// Credential lookup parameters.
#[derive(Debug, Clone)]
pub struct CredentialLookup {
    pub asset_id: Option<String>,
    pub credential_type: Option<String>,
}

impl CredentialLookup {
    /// Create a lookup for all credentials.
    pub fn all() -> Self {
        Self {
            asset_id: None,
            credential_type: None,
        }
    }

    /// Create a lookup for a specific asset.
    pub fn for_asset(asset_id: &str) -> Self {
        Self {
            asset_id: Some(asset_id.to_string()),
            credential_type: None,
        }
    }

    /// Filter by credential type.
    pub fn with_type(mut self, cred_type: &str) -> Self {
        self.credential_type = Some(cred_type.to_string());
        self
    }
}

/// Vault service wrapper.
pub struct VaultService {
    client: VaultClient,
}

impl VaultService {
    /// Create a new Vault service.
    pub async fn new(config: Config) -> AppResult<Self> {
        let client = VaultClient::new(&config).await?;
        Ok(Self { client })
    }

    /// List credentials for an asset.
    pub async fn list_credentials(&self, asset_id: Option<&str>) -> AppResult<Vec<String>> {
        self.client.list_credentials(asset_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== CredentialLookup Tests ====================

    #[test]
    fn test_credential_lookup_all() {
        let lookup = CredentialLookup::all();

        assert!(lookup.asset_id.is_none());
        assert!(lookup.credential_type.is_none());
    }

    #[test]
    fn test_credential_lookup_for_asset() {
        let lookup = CredentialLookup::for_asset("asset-123");

        assert_eq!(lookup.asset_id, Some("asset-123".to_string()));
        assert!(lookup.credential_type.is_none());
    }

    #[test]
    fn test_credential_lookup_with_type() {
        let lookup = CredentialLookup::for_asset("asset-456")
            .with_type("ssh_key");

        assert_eq!(lookup.asset_id, Some("asset-456".to_string()));
        assert_eq!(lookup.credential_type, Some("ssh_key".to_string()));
    }

    #[test]
    fn test_credential_lookup_clone() {
        let lookup = CredentialLookup::for_asset("asset-789")
            .with_type("password");
        let cloned = lookup.clone();

        assert_eq!(lookup.asset_id, cloned.asset_id);
        assert_eq!(lookup.credential_type, cloned.credential_type);
    }

    #[test]
    fn test_credential_lookup_debug() {
        let lookup = CredentialLookup::for_asset("server-01")
            .with_type("certificate");
        let debug_str = format!("{:?}", lookup);

        assert!(debug_str.contains("CredentialLookup"));
        assert!(debug_str.contains("server-01"));
        assert!(debug_str.contains("certificate"));
    }

    #[test]
    fn test_credential_lookup_chain_methods() {
        let lookup = CredentialLookup::all()
            .with_type("api_key");

        assert!(lookup.asset_id.is_none());
        assert_eq!(lookup.credential_type, Some("api_key".to_string()));
    }

    #[test]
    fn test_credential_lookup_common_types() {
        let types = ["password", "ssh_key", "certificate", "api_key", "token"];

        for cred_type in types {
            let lookup = CredentialLookup::all().with_type(cred_type);
            assert_eq!(lookup.credential_type, Some(cred_type.to_string()));
        }
    }
}

