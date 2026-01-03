/// VAUBAN Web - User model.
///
/// User model with MFA support, authentication tracking, and RBAC integration.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::users;

/// User authentication source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthSource {
    Local,
    Ldap,
    Oidc,
    Saml,
}

impl AuthSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Ldap => "ldap",
            Self::Oidc => "oidc",
            Self::Saml => "saml",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "ldap" => Self::Ldap,
            "oidc" => Self::Oidc,
            "saml" => Self::Saml,
            _ => Self::Local,
        }
    }
}

/// User database model.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: i32,
    pub uuid: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub is_active: bool,
    pub is_staff: bool,
    pub is_superuser: bool,
    pub is_service_account: bool,
    pub mfa_enabled: bool,
    pub mfa_enforced: bool,
    #[serde(skip_serializing)]
    pub mfa_secret: Option<String>,
    pub preferences: serde_json::Value,
    pub last_login: Option<DateTime<Utc>>,
    pub last_login_ip: Option<String>,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub auth_source: String,
    pub external_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_deleted: bool,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// New user for insertion.
#[derive(Debug, Clone, Insertable, AsChangeset)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub uuid: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub is_active: bool,
    pub is_staff: bool,
    pub is_superuser: bool,
    pub is_service_account: bool,
    pub mfa_enabled: bool,
    pub mfa_enforced: bool,
    pub mfa_secret: Option<String>,
    pub preferences: serde_json::Value,
    pub auth_source: String,
    pub external_id: Option<String>,
}

/// User update structure.
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = users)]
pub struct UserUpdate {
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub is_active: Option<bool>,
    pub preferences: Option<serde_json::Value>,
    pub updated_at: DateTime<Utc>,
}

/// User DTO for API responses (without sensitive data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDto {
    pub uuid: Uuid,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub is_active: bool,
    pub is_staff: bool,
    pub is_superuser: bool,
    pub is_service_account: bool,
    pub mfa_enabled: bool,
    pub mfa_enforced: bool,
    pub preferences: serde_json::Value,
    pub last_login: Option<DateTime<Utc>>,
    pub last_login_ip: Option<String>,
    pub auth_source: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Convert User to DTO (removes sensitive fields).
    pub fn to_dto(&self) -> UserDto {
        UserDto {
            uuid: self.uuid,
            username: self.username.clone(),
            email: self.email.clone(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            phone: self.phone.clone(),
            is_active: self.is_active,
            is_staff: self.is_staff,
            is_superuser: self.is_superuser,
            is_service_account: self.is_service_account,
            mfa_enabled: self.mfa_enabled,
            mfa_enforced: self.mfa_enforced,
            preferences: self.preferences.clone(),
            last_login: self.last_login,
            last_login_ip: self.last_login_ip.clone(),
            auth_source: self.auth_source.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    /// Get display name.
    pub fn display_name(&self) -> String {
        if let (Some(first), Some(last)) = (&self.first_name, &self.last_name) {
            format!("{} {}", first, last)
        } else {
            self.username.clone()
        }
    }

    /// Check if account is locked.
    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            locked_until > Utc::now()
        } else {
            false
        }
    }

    /// Get authentication source enum.
    pub fn auth_source_enum(&self) -> AuthSource {
        AuthSource::from_str(&self.auth_source)
    }

}

/// User creation request.
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct CreateUserRequest {
    #[validate(length(min = 3, max = 150))]
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 12))]
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub is_staff: Option<bool>,
    pub is_superuser: Option<bool>,
}

/// User update request.
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct UpdateUserRequest {
    #[validate(email)]
    pub email: Option<String>,
    #[validate(length(max = 150))]
    pub first_name: Option<String>,
    #[validate(length(max = 150))]
    pub last_name: Option<String>,
    #[validate(length(max = 20))]
    pub phone: Option<String>,
    pub is_active: Option<bool>,
    pub preferences: Option<serde_json::Value>,
}

