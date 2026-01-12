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
        let lookup = CredentialLookup::for_asset("asset-456").with_type("ssh_key");

        assert_eq!(lookup.asset_id, Some("asset-456".to_string()));
        assert_eq!(lookup.credential_type, Some("ssh_key".to_string()));
    }

    #[test]
    fn test_credential_lookup_clone() {
        let lookup = CredentialLookup::for_asset("asset-789").with_type("password");
        let cloned = lookup.clone();

        assert_eq!(lookup.asset_id, cloned.asset_id);
        assert_eq!(lookup.credential_type, cloned.credential_type);
    }

    #[test]
    fn test_credential_lookup_debug() {
        let lookup = CredentialLookup::for_asset("server-01").with_type("certificate");
        let debug_str = format!("{:?}", lookup);

        assert!(debug_str.contains("CredentialLookup"));
        assert!(debug_str.contains("server-01"));
        assert!(debug_str.contains("certificate"));
    }

    #[test]
    fn test_credential_lookup_chain_methods() {
        let lookup = CredentialLookup::all().with_type("api_key");

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

    // ==================== CredentialLookup Edge Cases ====================

    #[test]
    fn test_credential_lookup_empty_asset_id() {
        let lookup = CredentialLookup::for_asset("");
        assert_eq!(lookup.asset_id, Some("".to_string()));
    }

    #[test]
    fn test_credential_lookup_empty_type() {
        let lookup = CredentialLookup::all().with_type("");
        assert_eq!(lookup.credential_type, Some("".to_string()));
    }

    #[test]
    fn test_credential_lookup_unicode_asset_id() {
        let lookup = CredentialLookup::for_asset("资产-服务器-01");
        assert_eq!(lookup.asset_id, Some("资产-服务器-01".to_string()));
    }

    #[test]
    fn test_credential_lookup_unicode_type() {
        let lookup = CredentialLookup::all().with_type("密码类型");
        assert_eq!(lookup.credential_type, Some("密码类型".to_string()));
    }

    #[test]
    fn test_credential_lookup_long_asset_id() {
        let long_id = "a".repeat(500);
        let lookup = CredentialLookup::for_asset(&long_id);
        assert_eq!(lookup.asset_id.as_ref().map(|s| s.len()), Some(500));
    }

    #[test]
    fn test_credential_lookup_special_chars() {
        let lookup = CredentialLookup::for_asset("asset/with:special@chars#and$more");
        assert!(lookup.asset_id.is_some());
    }

    #[test]
    fn test_credential_lookup_with_type_overwrite() {
        let lookup = CredentialLookup::all()
            .with_type("first")
            .with_type("second");

        assert_eq!(lookup.credential_type, Some("second".to_string()));
    }

    #[test]
    fn test_credential_lookup_all_is_default() {
        let lookup = CredentialLookup::all();

        assert!(lookup.asset_id.is_none());
        assert!(lookup.credential_type.is_none());
    }

    #[test]
    fn test_credential_lookup_for_asset_preserves_none_type() {
        let lookup = CredentialLookup::for_asset("my-asset");

        assert!(lookup.asset_id.is_some());
        assert!(lookup.credential_type.is_none());
    }

    #[test]
    fn test_credential_lookup_clone_independence() {
        let mut lookup1 = CredentialLookup::for_asset("asset-1");
        let lookup2 = lookup1.clone();

        lookup1.asset_id = Some("modified".to_string());

        // Clone should not be affected
        assert_eq!(lookup2.asset_id, Some("asset-1".to_string()));
    }

    #[test]
    fn test_credential_lookup_debug_all() {
        let lookup = CredentialLookup::all();
        let debug_str = format!("{:?}", lookup);

        assert!(debug_str.contains("None"));
    }

    #[test]
    fn test_credential_lookup_multiple_assets() {
        let assets = ["server-01", "db-primary", "cache-redis", "queue-rabbitmq"];

        for asset in assets {
            let lookup = CredentialLookup::for_asset(asset);
            assert_eq!(lookup.asset_id, Some(asset.to_string()));
        }
    }

    #[test]
    fn test_credential_lookup_uuid_asset_id() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let lookup = CredentialLookup::for_asset(uuid);

        assert_eq!(lookup.asset_id, Some(uuid.to_string()));
    }

    // ==================== CredentialLookup Struct Fields ====================

    #[test]
    fn test_credential_lookup_direct_construction() {
        let lookup = CredentialLookup {
            asset_id: Some("direct-asset".to_string()),
            credential_type: Some("direct-type".to_string()),
        };

        assert_eq!(lookup.asset_id, Some("direct-asset".to_string()));
        assert_eq!(lookup.credential_type, Some("direct-type".to_string()));
    }

    #[test]
    fn test_credential_lookup_partial_construction() {
        let lookup = CredentialLookup {
            asset_id: None,
            credential_type: Some("only-type".to_string()),
        };

        assert!(lookup.asset_id.is_none());
        assert!(lookup.credential_type.is_some());
    }
}
