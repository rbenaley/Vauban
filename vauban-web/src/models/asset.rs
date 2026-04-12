/// VAUBAN Web - Asset model.
///
/// Assets represent servers/resources accessible via SSH or RDP.
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::schema::{asset_asset_groups, asset_groups, assets};

// ==================== Flexible Deserialization Helpers ====================

/// Deserialize an optional i32 from either a number or a string.
/// This is needed because HTML forms send all values as strings.
pub(crate) fn deserialize_optional_i32<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrInt {
        String(String),
        Int(i32),
    }

    let opt: Option<StringOrInt> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(StringOrInt::Int(i)) => Ok(Some(i)),
        Some(StringOrInt::String(s)) if s.is_empty() => Ok(None),
        Some(StringOrInt::String(s)) => s
            .parse::<i32>()
            .map(Some)
            .map_err(|_| D::Error::custom(format!("invalid integer: {}", s))),
    }
}

/// Asset type (protocol) (L-7: Diesel enum instead of String).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    diesel::expression::AsExpression,
    diesel::deserialize::FromSqlRow,
)]
#[serde(rename_all = "lowercase")]
#[diesel(sql_type = diesel::sql_types::Varchar)]
pub enum AssetType {
    Ssh,
    Rdp,
}

impl AssetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "rdp" => Self::Rdp,
            _ => Self::Ssh,
        }
    }

    /// Try to parse a string into an AssetType, returning None for unknown values.
    pub fn try_parse(s: &str) -> Option<Self> {
        match s {
            "ssh" => Some(Self::Ssh),
            "rdp" => Some(Self::Rdp),
            _ => None,
        }
    }

    pub fn default_port(&self) -> i32 {
        match self {
            Self::Ssh => 22,
            Self::Rdp => 3389,
        }
    }
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl diesel::serialize::ToSql<diesel::sql_types::Varchar, diesel::pg::Pg> for AssetType {
    fn to_sql<'b>(
        &'b self,
        out: &mut diesel::serialize::Output<'b, '_, diesel::pg::Pg>,
    ) -> diesel::serialize::Result {
        <str as diesel::serialize::ToSql<diesel::sql_types::Varchar, diesel::pg::Pg>>::to_sql(
            self.as_str(),
            out,
        )
    }
}

impl diesel::deserialize::FromSql<diesel::sql_types::Varchar, diesel::pg::Pg> for AssetType {
    fn from_sql(
        bytes: <diesel::pg::Pg as diesel::backend::Backend>::RawValue<'_>,
    ) -> diesel::deserialize::Result<Self> {
        let s = <String as diesel::deserialize::FromSql<
            diesel::sql_types::Varchar,
            diesel::pg::Pg,
        >>::from_sql(bytes)?;
        Ok(Self::parse(&s))
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

    pub fn parse(s: &str) -> Self {
        match s {
            "online" => Self::Online,
            "offline" => Self::Offline,
            "maintenance" => Self::Maintenance,
            _ => Self::Unknown,
        }
    }
}

/// Asset database model.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize)]
#[diesel(table_name = assets)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Asset {
    pub id: i32,
    pub uuid: Uuid,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: AssetType,
    pub status: String,
    pub description: Option<String>,
    pub connection_config: serde_json::Value,
    pub created_by_id: Option<i32>,
    pub updated_by_id: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_deleted: bool,
    pub deleted_at: Option<DateTime<Utc>>,
    pub connection_username: String,
}

/// New asset for insertion.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = assets)]
pub struct NewAsset {
    pub uuid: Uuid,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: AssetType,
    pub status: String,
    pub description: Option<String>,
    pub connection_config: serde_json::Value,
    pub created_by_id: Option<i32>,
    pub connection_username: String,
}

/// Row in `asset_asset_groups` (many-to-many).
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = asset_asset_groups)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AssetAssetGroup {
    pub asset_id: i32,
    pub asset_group_id: i32,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = asset_asset_groups)]
pub struct NewAssetAssetGroup {
    pub asset_id: i32,
    pub asset_group_id: i32,
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
    /// Get status enum.
    pub fn status_enum(&self) -> AssetStatus {
        AssetStatus::parse(&self.status)
    }

    /// Get connection string.
    pub fn connection_string(&self) -> String {
        format!("{}@{}:{}", self.connection_username, self.hostname, self.port)
    }
}

/// Asset creation request.
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct CreateAssetRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[validate(length(min = 1, max = 255))]
    pub hostname: String,
    #[validate(range(min = 1, max = 65535))]
    pub port: Option<i32>,
    pub asset_type: AssetType,
    /// Legacy single group (use `group_ids` when assigning multiple).
    #[serde(default)]
    pub group_id: Option<i32>,
    /// Asset group IDs to link after creation.
    #[serde(default)]
    pub group_ids: Vec<i32>,
    pub description: Option<String>,
}

/// Asset update request.
///
/// Supports flexible deserialization for HTML form submissions where
/// numbers are sent as strings and checkboxes send "on" or are absent.
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct UpdateAssetRequest {
    #[validate(length(max = 100))]
    pub name: Option<String>,
    #[validate(length(max = 255))]
    pub hostname: Option<String>,
    #[validate(range(min = 1, max = 65535))]
    #[serde(default, deserialize_with = "deserialize_optional_i32")]
    pub port: Option<i32>,
    pub status: Option<String>,
    pub description: Option<String>,
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
            port: 22,
            asset_type: AssetType::Ssh,
            status: "online".to_string(),
            description: Some("A test server".to_string()),
            connection_config: serde_json::json!({}),
            created_by_id: None,
            updated_by_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_deleted: false,
            deleted_at: None,
            connection_username: "root".to_string(),
        }
    }

    // ==================== AssetType Tests ====================

    #[test]
    fn test_asset_type_from_str_ssh() {
        assert_eq!(AssetType::parse("ssh"), AssetType::Ssh);
    }

    #[test]
    fn test_asset_type_from_str_rdp() {
        assert_eq!(AssetType::parse("rdp"), AssetType::Rdp);
    }

    #[test]
    fn test_asset_type_from_str_unknown() {
        // Unknown values default to SSH
        assert_eq!(AssetType::parse("unknown"), AssetType::Ssh);
        assert_eq!(AssetType::parse(""), AssetType::Ssh);
        assert_eq!(AssetType::parse("SSH"), AssetType::Ssh); // Case sensitive, defaults to SSH
    }

    #[test]
    fn test_asset_type_as_str() {
        assert_eq!(AssetType::Ssh.as_str(), "ssh");
        assert_eq!(AssetType::Rdp.as_str(), "rdp");
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
    fn test_asset_type_roundtrip() {
        for asset_type in [AssetType::Ssh, AssetType::Rdp] {
            let str_val = asset_type.as_str();
            let parsed = AssetType::parse(str_val);
            assert_eq!(asset_type, parsed);
        }
    }

    // ==================== AssetStatus Tests ====================

    #[test]
    fn test_asset_status_from_str_online() {
        assert_eq!(AssetStatus::parse("online"), AssetStatus::Online);
    }

    #[test]
    fn test_asset_status_from_str_offline() {
        assert_eq!(AssetStatus::parse("offline"), AssetStatus::Offline);
    }

    #[test]
    fn test_asset_status_from_str_maintenance() {
        assert_eq!(AssetStatus::parse("maintenance"), AssetStatus::Maintenance);
    }

    #[test]
    fn test_asset_status_from_str_unknown() {
        assert_eq!(AssetStatus::parse("unknown"), AssetStatus::Unknown);
        assert_eq!(AssetStatus::parse("invalid"), AssetStatus::Unknown);
        assert_eq!(AssetStatus::parse(""), AssetStatus::Unknown);
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
            let parsed = AssetStatus::parse(str_val);
            assert_eq!(status, parsed);
        }
    }

    // ==================== Asset Method Tests ====================

    #[test]
    fn test_asset_type_field_is_enum() {
        let asset = create_test_asset();
        assert_eq!(asset.asset_type, AssetType::Ssh);
    }

    #[test]
    fn test_asset_status_enum() {
        let asset = create_test_asset();
        assert_eq!(asset.status_enum(), AssetStatus::Online);
    }

    #[test]
    fn test_asset_connection_string() {
        let asset = create_test_asset();
        assert_eq!(asset.connection_string(), "root@test.example.com:22");
    }

    #[test]
    fn test_asset_connection_string_different_port() {
        let mut asset = create_test_asset();
        asset.port = 2222;
        asset.hostname = "server.local".to_string();
        asset.connection_username = "deploy".to_string();
        assert_eq!(asset.connection_string(), "deploy@server.local:2222");
    }

    // ==================== Validation Tests ====================

    #[test]
    fn test_create_asset_request_validation_valid() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "My Server".to_string(),
            hostname: "server.example.com".to_string(),
            port: Some(22),
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_asset_request_validation_empty_name() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "".to_string(), // Empty name (min 1)
            hostname: "server.example.com".to_string(),
            port: None,
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_asset_request_validation_invalid_port() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "My Server".to_string(),
            hostname: "server.example.com".to_string(),
            port: Some(70000), // Invalid port (max 65535)
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_asset_request_validation_port_zero() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "My Server".to_string(),
            hostname: "server.example.com".to_string(),
            port: Some(0), // Invalid port (min 1)
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        assert!(request.validate().is_err());
    }

    // ==================== AssetType Additional Tests ====================

    #[test]
    fn test_asset_type_debug() {
        let asset_type = AssetType::Ssh;
        let debug_str = format!("{:?}", asset_type);
        assert!(debug_str.contains("Ssh"));
    }

    #[test]
    fn test_asset_type_clone() {
        let asset_type = AssetType::Rdp;
        let cloned = asset_type;
        assert_eq!(asset_type, cloned);
    }

    #[test]
    fn test_asset_type_copy() {
        let asset_type = AssetType::Rdp;
        let copied = asset_type;
        assert_eq!(asset_type, copied);
    }

    #[test]
    fn test_asset_type_serialize() {
        let asset_type = AssetType::Ssh;
        let json = unwrap_ok!(serde_json::to_string(&asset_type));
        assert!(json.contains("ssh"));
    }

    #[test]
    fn test_asset_type_deserialize() {
        let json = r#""rdp""#;
        let asset_type: AssetType = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(asset_type, AssetType::Rdp);
    }

    #[test]
    fn test_asset_type_display() {
        assert_eq!(AssetType::Ssh.to_string(), "ssh");
        assert_eq!(AssetType::Rdp.to_string(), "rdp");
    }

    // ==================== AssetStatus Additional Tests ====================

    #[test]
    fn test_asset_status_debug() {
        let status = AssetStatus::Online;
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("Online"));
    }

    #[test]
    fn test_asset_status_clone() {
        let status = AssetStatus::Offline;
        let cloned = status;
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_asset_status_copy() {
        let status = AssetStatus::Maintenance;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn test_asset_status_serialize() {
        let status = AssetStatus::Unknown;
        let json = unwrap_ok!(serde_json::to_string(&status));
        assert!(json.contains("Unknown"));
    }

    // ==================== Asset Additional Tests ====================

    #[test]
    fn test_asset_clone() {
        let asset = create_test_asset();
        let cloned = asset.clone();
        assert_eq!(asset.uuid, cloned.uuid);
        assert_eq!(asset.name, cloned.name);
    }

    #[test]
    fn test_asset_debug() {
        let asset = create_test_asset();
        let debug_str = format!("{:?}", asset);
        assert!(debug_str.contains("Asset"));
        assert!(debug_str.contains("Test Server"));
    }

    #[test]
    fn test_asset_serialize() {
        let asset = create_test_asset();
        let json = unwrap_ok!(serde_json::to_string(&asset));
        assert!(json.contains("Test Server"));
    }

    #[test]
    fn test_asset_type_field_rdp() {
        let mut asset = create_test_asset();
        asset.asset_type = AssetType::Rdp;
        assert_eq!(asset.asset_type, AssetType::Rdp);
    }

    #[test]
    fn test_asset_status_enum_offline() {
        let mut asset = create_test_asset();
        asset.status = "offline".to_string();
        assert_eq!(asset.status_enum(), AssetStatus::Offline);
    }

    #[test]
    fn test_asset_status_enum_maintenance() {
        let mut asset = create_test_asset();
        asset.status = "maintenance".to_string();
        assert_eq!(asset.status_enum(), AssetStatus::Maintenance);
    }

    // ==================== NewAsset Tests ====================

    #[test]
    fn test_new_asset_debug() {
        let new_asset = NewAsset {
            uuid: Uuid::new_v4(),
            name: "New Asset".to_string(),
            hostname: "new.example.com".to_string(),
            port: 22,
            asset_type: AssetType::Ssh,
            status: "unknown".to_string(),
            description: None,
            connection_config: serde_json::json!({}),
            created_by_id: None,
            connection_username: "root".to_string(),
        };

        let debug_str = format!("{:?}", new_asset);
        assert!(debug_str.contains("NewAsset"));
    }

    #[test]
    fn test_new_asset_clone() {
        let new_asset = NewAsset {
            uuid: Uuid::new_v4(),
            name: "Clone Asset".to_string(),
            hostname: "clone.example.com".to_string(),
            port: 3389,
            asset_type: AssetType::Rdp,
            status: "online".to_string(),
            description: Some("A cloned asset".to_string()),
            connection_config: serde_json::json!({"key": "value"}),
            created_by_id: Some(1),
            connection_username: "Administrator".to_string(),
        };

        let cloned = new_asset.clone();
        assert_eq!(new_asset.name, cloned.name);
    }

    // ==================== AssetGroup Tests ====================

    #[test]
    fn test_asset_group_debug() {
        let group = AssetGroup {
            id: 1,
            uuid: Uuid::new_v4(),
            name: "Test Group".to_string(),
            slug: "test-group".to_string(),
            description: Some("A test group".to_string()),
            color: "#FF0000".to_string(),
            icon: "folder".to_string(),
            parent_id: None,
            created_by_id: None,
            updated_by_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_deleted: false,
            deleted_at: None,
        };

        let debug_str = format!("{:?}", group);
        assert!(debug_str.contains("AssetGroup"));
    }

    #[test]
    fn test_asset_group_clone() {
        let group = AssetGroup {
            id: 1,
            uuid: Uuid::new_v4(),
            name: "Clone Group".to_string(),
            slug: "clone-group".to_string(),
            description: None,
            color: "#00FF00".to_string(),
            icon: "server".to_string(),
            parent_id: Some(2),
            created_by_id: Some(1),
            updated_by_id: Some(1),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_deleted: false,
            deleted_at: None,
        };

        let cloned = group.clone();
        assert_eq!(group.name, cloned.name);
    }

    #[test]
    fn test_asset_group_serialize() {
        let group = AssetGroup {
            id: 1,
            uuid: Uuid::new_v4(),
            name: "Serialize Group".to_string(),
            slug: "serialize-group".to_string(),
            description: None,
            color: "#0000FF".to_string(),
            icon: "database".to_string(),
            parent_id: None,
            created_by_id: None,
            updated_by_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_deleted: false,
            deleted_at: None,
        };

        let json = unwrap_ok!(serde_json::to_string(&group));
        assert!(json.contains("Serialize Group"));
    }

    // ==================== CreateAssetRequest Additional Tests ====================

    #[test]
    fn test_create_asset_request_debug() {
        let request = CreateAssetRequest {
            name: "Debug Server".to_string(),
            hostname: "debug.example.com".to_string(),
            port: None,
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("CreateAssetRequest"));
    }

    #[test]
    fn test_create_asset_request_clone() {
        let request = CreateAssetRequest {
            name: "Clone Server".to_string(),
            hostname: "clone.example.com".to_string(),
            port: Some(22),
            asset_type: AssetType::Ssh,
            group_id: Some(1),
            group_ids: vec![],
            description: Some("Cloned".to_string()),
        };

        let cloned = request.clone();
        assert_eq!(request.name, cloned.name);
    }

    #[test]
    fn test_create_asset_request_long_name_invalid() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "A".repeat(101), // Too long
            hostname: "server.example.com".to_string(),
            port: None,
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_asset_request_long_hostname_invalid() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "Server".to_string(),
            hostname: "a".repeat(256), // Too long
            port: None,
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        assert!(request.validate().is_err());
    }

    // ==================== UpdateAssetRequest Tests ====================

    #[test]
    fn test_update_asset_request_debug() {
        let request = UpdateAssetRequest {
            name: Some("Updated".to_string()),
            hostname: None,
            port: None,
            status: None,
            description: None,
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("UpdateAssetRequest"));
    }

    #[test]
    fn test_update_asset_request_clone() {
        let request = UpdateAssetRequest {
            name: Some("Clone".to_string()),
            hostname: Some("clone.example.com".to_string()),
            port: Some(2222),
            status: Some("maintenance".to_string()),
            description: Some("Updated description".to_string()),
        };

        let cloned = request.clone();
        assert_eq!(request.name, cloned.name);
    }

    // ==================== Flexible Deserialization Tests ====================

    #[test]
    fn test_update_asset_request_port_as_string() {
        let json = r#"{"port": "22"}"#;
        let request: UpdateAssetRequest = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(request.port, Some(22));
    }

    #[test]
    fn test_update_asset_request_port_as_integer() {
        let json = r#"{"port": 22}"#;
        let request: UpdateAssetRequest = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(request.port, Some(22));
    }

    #[test]
    fn test_update_asset_request_port_empty_string() {
        let json = r#"{"port": ""}"#;
        let request: UpdateAssetRequest = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(request.port, None);
    }

    #[test]
    fn test_update_asset_request_port_null() {
        let json = r#"{"port": null}"#;
        let request: UpdateAssetRequest = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(request.port, None);
    }

    #[test]
    fn test_update_asset_request_form_like_json() {
        let json = r#"{
            "name": "test-server",
            "hostname": "test.example.com",
            "port": "22",
            "status": "online",
            "description": "Test server"
        }"#;
        let request: UpdateAssetRequest = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(request.name, Some("test-server".to_string()));
        assert_eq!(request.port, Some(22));
    }

    // ==================== deserialize_optional_i32 Tests ====================

    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct OptI32Wrapper {
        #[serde(default, deserialize_with = "deserialize_optional_i32")]
        value: Option<i32>,
    }

    #[test]
    fn test_deserialize_optional_i32_from_integer() {
        let json = r#"{"value": 42}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, Some(42));
    }

    #[test]
    fn test_deserialize_optional_i32_from_string_number() {
        let json = r#"{"value": "99"}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, Some(99));
    }

    #[test]
    fn test_deserialize_optional_i32_from_empty_string() {
        let json = r#"{"value": ""}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, None);
    }

    #[test]
    fn test_deserialize_optional_i32_from_null() {
        let json = r#"{"value": null}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, None);
    }

    #[test]
    fn test_deserialize_optional_i32_missing_field() {
        let json = r#"{}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, None);
    }

    #[test]
    fn test_deserialize_optional_i32_negative() {
        let json = r#"{"value": -5}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, Some(-5));
    }

    #[test]
    fn test_deserialize_optional_i32_negative_string() {
        let json = r#"{"value": "-10"}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, Some(-10));
    }

    #[test]
    fn test_deserialize_optional_i32_zero() {
        let json = r#"{"value": 0}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, Some(0));
    }

    #[test]
    fn test_deserialize_optional_i32_zero_string() {
        let json = r#"{"value": "0"}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, Some(0));
    }

    #[test]
    fn test_deserialize_optional_i32_invalid_string_fails() {
        let json = r#"{"value": "abc"}"#;
        let result: Result<OptI32Wrapper, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_optional_i32_float_string_fails() {
        let json = r#"{"value": "3.14"}"#;
        let result: Result<OptI32Wrapper, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_optional_i32_whitespace_only_fails() {
        let json = r#"{"value": "  "}"#;
        let result: Result<OptI32Wrapper, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_optional_i32_max_value() {
        let json = format!(r#"{{"value": {}}}"#, i32::MAX);
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(&json));
        assert_eq!(w.value, Some(i32::MAX));
    }

    #[test]
    fn test_deserialize_optional_i32_min_value() {
        let json = format!(r#"{{"value": {}}}"#, i32::MIN);
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(&json));
        assert_eq!(w.value, Some(i32::MIN));
    }
}
