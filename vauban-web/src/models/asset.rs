/// VAUBAN Web - Asset model.
///
/// Assets represent servers/resources accessible via SSH, RDP, or VNC.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
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
    pub ip_address: Option<String>,
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
    pub ip_address: Option<String>,
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

