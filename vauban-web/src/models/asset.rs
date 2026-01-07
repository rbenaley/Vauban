/// VAUBAN Web - Asset model.
///
/// Assets represent servers/resources accessible via SSH, RDP, or VNC.
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::{asset_groups, assets};

/// Asset type (protocol).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetType {
    Ssh,
    Rdp,
    Vnc,
}

impl AssetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Vnc => "vnc",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "rdp" => Self::Rdp,
            "vnc" => Self::Vnc,
            _ => Self::Ssh,
        }
    }

    pub fn default_port(&self) -> i32 {
        match self {
            Self::Ssh => 22,
            Self::Rdp => 3389,
            Self::Vnc => 5900,
        }
    }
}

/// Asset status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetStatus {
    Online,
    Offline,
    Maintenance,
    Unknown,
}

impl AssetStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Maintenance => "maintenance",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "online" => Self::Online,
            "offline" => Self::Offline,
            "maintenance" => Self::Maintenance,
            _ => Self::Unknown,
        }
    }
}

/// Asset database model.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Associations, Serialize)]
#[diesel(table_name = assets)]
#[diesel(belongs_to(AssetGroup, foreign_key = group_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Asset {
    pub id: i32,
    pub uuid: Uuid,
    pub name: String,
    pub hostname: String,
    #[serde(skip_serializing)]
    pub ip_address: Option<IpNetwork>,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub group_id: Option<i32>,
    pub description: Option<String>,
    pub os_type: Option<String>,
    pub os_version: Option<String>,
    pub connection_config: serde_json::Value,
    pub default_credential_id: Option<String>,
    pub require_mfa: bool,
    pub require_justification: bool,
    pub max_session_duration: i32,
    pub last_seen: Option<DateTime<Utc>>,
    pub created_by_id: Option<i32>,
    pub updated_by_id: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_deleted: bool,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// New asset for insertion.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = assets)]
pub struct NewAsset {
    pub uuid: Uuid,
    pub name: String,
    pub hostname: String,
    pub ip_address: Option<IpNetwork>,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub group_id: Option<i32>,
    pub description: Option<String>,
    pub os_type: Option<String>,
    pub os_version: Option<String>,
    pub connection_config: serde_json::Value,
    pub default_credential_id: Option<String>,
    pub require_mfa: bool,
    pub require_justification: bool,
    pub max_session_duration: i32,
    pub created_by_id: Option<i32>,
}

/// Asset group database model.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize)]
#[diesel(table_name = asset_groups)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AssetGroup {
    pub id: i32,
    pub uuid: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
    pub parent_id: Option<i32>,
    pub created_by_id: Option<i32>,
    pub updated_by_id: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_deleted: bool,
    pub deleted_at: Option<DateTime<Utc>>,
}

impl Asset {
    /// Get asset type enum.
    pub fn asset_type_enum(&self) -> AssetType {
        AssetType::from_str(&self.asset_type)
    }

    /// Get status enum.
    pub fn status_enum(&self) -> AssetStatus {
        AssetStatus::from_str(&self.status)
    }

    /// Get connection string.
    pub fn connection_string(&self) -> String {
        format!("{}:{}", self.hostname, self.port)
    }
}

/// Asset creation request.
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct CreateAssetRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[validate(length(min = 1, max = 255))]
    pub hostname: String,
    pub ip_address: Option<String>,
    #[validate(range(min = 1, max = 65535))]
    pub port: Option<i32>,
    pub asset_type: String,
    pub group_id: Option<i32>,
    pub description: Option<String>,
    pub require_mfa: Option<bool>,
    pub require_justification: Option<bool>,
}

/// Asset update request.
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct UpdateAssetRequest {
    #[validate(length(max = 100))]
    pub name: Option<String>,
    #[validate(length(max = 255))]
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    #[validate(range(min = 1, max = 65535))]
    pub port: Option<i32>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub require_mfa: Option<bool>,
    pub require_justification: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test asset
    fn create_test_asset() -> Asset {
        Asset {
            id: 1,
            uuid: Uuid::new_v4(),
            name: "Test Server".to_string(),
            hostname: "test.example.com".to_string(),
            ip_address: Some("192.168.1.100/32".parse().unwrap()),
            port: 22,
            asset_type: "ssh".to_string(),
            status: "online".to_string(),
            group_id: None,
            description: Some("A test server".to_string()),
            os_type: Some("Linux".to_string()),
            os_version: Some("Ubuntu 22.04".to_string()),
            connection_config: serde_json::json!({}),
            default_credential_id: None,
            require_mfa: false,
            require_justification: false,
            max_session_duration: 28800,
            last_seen: None,
            created_by_id: None,
            updated_by_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_deleted: false,
            deleted_at: None,
        }
    }

    // ==================== AssetType Tests ====================

    #[test]
    fn test_asset_type_from_str_ssh() {
        assert_eq!(AssetType::from_str("ssh"), AssetType::Ssh);
    }

    #[test]
    fn test_asset_type_from_str_rdp() {
        assert_eq!(AssetType::from_str("rdp"), AssetType::Rdp);
    }

    #[test]
    fn test_asset_type_from_str_vnc() {
        assert_eq!(AssetType::from_str("vnc"), AssetType::Vnc);
    }

    #[test]
    fn test_asset_type_from_str_unknown() {
        // Unknown values default to SSH
        assert_eq!(AssetType::from_str("unknown"), AssetType::Ssh);
        assert_eq!(AssetType::from_str(""), AssetType::Ssh);
        assert_eq!(AssetType::from_str("SSH"), AssetType::Ssh); // Case sensitive, defaults to SSH
    }

    #[test]
    fn test_asset_type_as_str() {
        assert_eq!(AssetType::Ssh.as_str(), "ssh");
        assert_eq!(AssetType::Rdp.as_str(), "rdp");
        assert_eq!(AssetType::Vnc.as_str(), "vnc");
    }

    #[test]
    fn test_asset_type_default_port_ssh() {
        assert_eq!(AssetType::Ssh.default_port(), 22);
    }

    #[test]
    fn test_asset_type_default_port_rdp() {
        assert_eq!(AssetType::Rdp.default_port(), 3389);
    }

    #[test]
    fn test_asset_type_default_port_vnc() {
        assert_eq!(AssetType::Vnc.default_port(), 5900);
    }

    #[test]
    fn test_asset_type_roundtrip() {
        for asset_type in [AssetType::Ssh, AssetType::Rdp, AssetType::Vnc] {
            let str_val = asset_type.as_str();
            let parsed = AssetType::from_str(str_val);
            assert_eq!(asset_type, parsed);
        }
    }

    // ==================== AssetStatus Tests ====================

    #[test]
    fn test_asset_status_from_str_online() {
        assert_eq!(AssetStatus::from_str("online"), AssetStatus::Online);
    }

    #[test]
    fn test_asset_status_from_str_offline() {
        assert_eq!(AssetStatus::from_str("offline"), AssetStatus::Offline);
    }

    #[test]
    fn test_asset_status_from_str_maintenance() {
        assert_eq!(
            AssetStatus::from_str("maintenance"),
            AssetStatus::Maintenance
        );
    }

    #[test]
    fn test_asset_status_from_str_unknown() {
        assert_eq!(AssetStatus::from_str("unknown"), AssetStatus::Unknown);
        assert_eq!(AssetStatus::from_str("invalid"), AssetStatus::Unknown);
        assert_eq!(AssetStatus::from_str(""), AssetStatus::Unknown);
    }

    #[test]
    fn test_asset_status_as_str() {
        assert_eq!(AssetStatus::Online.as_str(), "online");
        assert_eq!(AssetStatus::Offline.as_str(), "offline");
        assert_eq!(AssetStatus::Maintenance.as_str(), "maintenance");
        assert_eq!(AssetStatus::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_asset_status_roundtrip() {
        for status in [
            AssetStatus::Online,
            AssetStatus::Offline,
            AssetStatus::Maintenance,
            AssetStatus::Unknown,
        ] {
            let str_val = status.as_str();
            let parsed = AssetStatus::from_str(str_val);
            assert_eq!(status, parsed);
        }
    }

    // ==================== Asset Method Tests ====================

    #[test]
    fn test_asset_type_enum() {
        let asset = create_test_asset();
        assert_eq!(asset.asset_type_enum(), AssetType::Ssh);
    }

    #[test]
    fn test_asset_status_enum() {
        let asset = create_test_asset();
        assert_eq!(asset.status_enum(), AssetStatus::Online);
    }

    #[test]
    fn test_asset_connection_string() {
        let asset = create_test_asset();
        assert_eq!(asset.connection_string(), "test.example.com:22");
    }

    #[test]
    fn test_asset_connection_string_different_port() {
        let mut asset = create_test_asset();
        asset.port = 2222;
        asset.hostname = "server.local".to_string();
        assert_eq!(asset.connection_string(), "server.local:2222");
    }

    // ==================== Validation Tests ====================

    #[test]
    fn test_create_asset_request_validation_valid() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "My Server".to_string(),
            hostname: "server.example.com".to_string(),
            ip_address: Some("192.168.1.1".to_string()),
            port: Some(22),
            asset_type: "ssh".to_string(),
            group_id: None,
            description: None,
            require_mfa: None,
            require_justification: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_asset_request_validation_empty_name() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "".to_string(), // Empty name (min 1)
            hostname: "server.example.com".to_string(),
            ip_address: None,
            port: None,
            asset_type: "ssh".to_string(),
            group_id: None,
            description: None,
            require_mfa: None,
            require_justification: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_asset_request_validation_invalid_port() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "My Server".to_string(),
            hostname: "server.example.com".to_string(),
            ip_address: None,
            port: Some(70000), // Invalid port (max 65535)
            asset_type: "ssh".to_string(),
            group_id: None,
            description: None,
            require_mfa: None,
            require_justification: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_asset_request_validation_port_zero() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "My Server".to_string(),
            hostname: "server.example.com".to_string(),
            ip_address: None,
            port: Some(0), // Invalid port (min 1)
            asset_type: "ssh".to_string(),
            group_id: None,
            description: None,
            require_mfa: None,
            require_justification: None,
        };

        assert!(request.validate().is_err());
    }
}
