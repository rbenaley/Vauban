/// VAUBAN Web - User model.
///
/// User model with MFA support, authentication tracking, and RBAC integration.
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use ipnetwork::IpNetwork;
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
    #[serde(skip_serializing)]
    pub last_login_ip: Option<IpNetwork>,
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
            last_login_ip: self.last_login_ip.map(|ip| ip.to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    /// Helper to create a test user
    fn create_test_user() -> User {
        User {
            id: 1,
            uuid: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hashed_password".to_string(),
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            phone: Some("+1234567890".to_string()),
            is_active: true,
            is_staff: false,
            is_superuser: false,
            is_service_account: false,
            mfa_enabled: false,
            mfa_enforced: false,
            mfa_secret: None,
            preferences: serde_json::json!({}),
            last_login: None,
            last_login_ip: None,
            failed_login_attempts: 0,
            locked_until: None,
            auth_source: "local".to_string(),
            external_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_deleted: false,
            deleted_at: None,
        }
    }

    // ==================== AuthSource Tests ====================

    #[test]
    fn test_auth_source_from_str_local() {
        assert_eq!(AuthSource::from_str("local"), AuthSource::Local);
    }

    #[test]
    fn test_auth_source_from_str_ldap() {
        assert_eq!(AuthSource::from_str("ldap"), AuthSource::Ldap);
    }

    #[test]
    fn test_auth_source_from_str_oidc() {
        assert_eq!(AuthSource::from_str("oidc"), AuthSource::Oidc);
    }

    #[test]
    fn test_auth_source_from_str_saml() {
        assert_eq!(AuthSource::from_str("saml"), AuthSource::Saml);
    }

    #[test]
    fn test_auth_source_from_str_unknown() {
        // Unknown values default to Local
        assert_eq!(AuthSource::from_str("unknown"), AuthSource::Local);
        assert_eq!(AuthSource::from_str(""), AuthSource::Local);
        assert_eq!(AuthSource::from_str("LDAP"), AuthSource::Local); // Case sensitive
    }

    #[test]
    fn test_auth_source_as_str() {
        assert_eq!(AuthSource::Local.as_str(), "local");
        assert_eq!(AuthSource::Ldap.as_str(), "ldap");
        assert_eq!(AuthSource::Oidc.as_str(), "oidc");
        assert_eq!(AuthSource::Saml.as_str(), "saml");
    }

    #[test]
    fn test_auth_source_roundtrip() {
        for source in [
            AuthSource::Local,
            AuthSource::Ldap,
            AuthSource::Oidc,
            AuthSource::Saml,
        ] {
            let str_val = source.as_str();
            let parsed = AuthSource::from_str(str_val);
            assert_eq!(source, parsed);
        }
    }

    // ==================== User::to_dto Tests ====================

    #[test]
    fn test_user_to_dto_copies_fields() {
        let user = create_test_user();
        let dto = user.to_dto();

        assert_eq!(dto.uuid, user.uuid);
        assert_eq!(dto.username, user.username);
        assert_eq!(dto.email, user.email);
        assert_eq!(dto.first_name, user.first_name);
        assert_eq!(dto.last_name, user.last_name);
        assert_eq!(dto.phone, user.phone);
        assert_eq!(dto.is_active, user.is_active);
        assert_eq!(dto.is_staff, user.is_staff);
        assert_eq!(dto.is_superuser, user.is_superuser);
        assert_eq!(dto.is_service_account, user.is_service_account);
        assert_eq!(dto.mfa_enabled, user.mfa_enabled);
        assert_eq!(dto.mfa_enforced, user.mfa_enforced);
        assert_eq!(dto.auth_source, user.auth_source);
    }

    #[test]
    fn test_user_to_dto_excludes_sensitive_fields() {
        let mut user = create_test_user();
        user.password_hash = "super_secret_hash".to_string();
        user.mfa_secret = Some("totp_secret".to_string());

        let dto = user.to_dto();

        // DTO should not have password_hash or mfa_secret fields
        let dto_json = serde_json::to_value(&dto).unwrap();
        assert!(dto_json.get("password_hash").is_none());
        assert!(dto_json.get("mfa_secret").is_none());
    }

    // ==================== User::display_name Tests ====================

    #[test]
    fn test_display_name_with_first_and_last() {
        let user = create_test_user();
        assert_eq!(user.display_name(), "John Doe");
    }

    #[test]
    fn test_display_name_without_first_name() {
        let mut user = create_test_user();
        user.first_name = None;
        assert_eq!(user.display_name(), "testuser");
    }

    #[test]
    fn test_display_name_without_last_name() {
        let mut user = create_test_user();
        user.last_name = None;
        assert_eq!(user.display_name(), "testuser");
    }

    #[test]
    fn test_display_name_without_both_names() {
        let mut user = create_test_user();
        user.first_name = None;
        user.last_name = None;
        assert_eq!(user.display_name(), "testuser");
    }

    // ==================== User::is_locked Tests ====================

    #[test]
    fn test_is_locked_when_not_locked() {
        let user = create_test_user();
        assert!(!user.is_locked());
    }

    #[test]
    fn test_is_locked_when_locked_in_future() {
        let mut user = create_test_user();
        user.locked_until = Some(Utc::now() + Duration::hours(1));
        assert!(user.is_locked());
    }

    #[test]
    fn test_is_locked_when_lock_expired() {
        let mut user = create_test_user();
        user.locked_until = Some(Utc::now() - Duration::hours(1));
        assert!(!user.is_locked());
    }

    // ==================== User::auth_source_enum Tests ====================

    #[test]
    fn test_auth_source_enum_local() {
        let user = create_test_user();
        assert_eq!(user.auth_source_enum(), AuthSource::Local);
    }

    #[test]
    fn test_auth_source_enum_ldap() {
        let mut user = create_test_user();
        user.auth_source = "ldap".to_string();
        assert_eq!(user.auth_source_enum(), AuthSource::Ldap);
    }

    // ==================== Validation Tests ====================

    #[test]
    fn test_create_user_request_validation_valid() {
        use validator::Validate;

        let request = CreateUserRequest {
            username: "validuser".to_string(),
            email: "valid@example.com".to_string(),
            password: "ValidPassword123!".to_string(),
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            phone: None,
            is_staff: None,
            is_superuser: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_user_request_validation_short_username() {
        use validator::Validate;

        let request = CreateUserRequest {
            username: "ab".to_string(), // Too short (min 3)
            email: "valid@example.com".to_string(),
            password: "ValidPassword123!".to_string(),
            first_name: None,
            last_name: None,
            phone: None,
            is_staff: None,
            is_superuser: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_user_request_validation_invalid_email() {
        use validator::Validate;

        let request = CreateUserRequest {
            username: "validuser".to_string(),
            email: "not-an-email".to_string(), // Invalid email
            password: "ValidPassword123!".to_string(),
            first_name: None,
            last_name: None,
            phone: None,
            is_staff: None,
            is_superuser: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_user_request_validation_short_password() {
        use validator::Validate;

        let request = CreateUserRequest {
            username: "validuser".to_string(),
            email: "valid@example.com".to_string(),
            password: "short".to_string(), // Too short (min 12)
            first_name: None,
            last_name: None,
            phone: None,
            is_staff: None,
            is_superuser: None,
        };

        assert!(request.validate().is_err());
    }
}
