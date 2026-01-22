/// VAUBAN Web - User model.
///
/// User model with MFA support, authentication tracking, and RBAC integration.
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::users;

// =============================================================================
// Validation Helpers
// =============================================================================

lazy_static::lazy_static! {
    /// Regex for valid usernames: alphanumeric, underscore, hyphen, dot.
    /// Must start with a letter or number.
    // SAFETY: Regex pattern is a compile-time constant, parsing cannot fail
    pub static ref RE_USERNAME: regex::Regex = {
        #[allow(clippy::expect_used)]
        regex::Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
            .expect("Invalid username regex")
    };
}

/// Validate password complexity.
///
/// Requirements:
/// - Minimum 12 characters
/// - At least one uppercase letter
/// - At least one lowercase letter
/// - At least one digit
/// - At least one special character
pub fn validate_password_complexity(password: &str) -> Result<(), validator::ValidationError> {
    if password.len() < 12 {
        return Err(validator::ValidationError::new("password_too_short"));
    }

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !has_uppercase {
        return Err(validator::ValidationError::new("password_missing_uppercase"));
    }
    if !has_lowercase {
        return Err(validator::ValidationError::new("password_missing_lowercase"));
    }
    if !has_digit {
        return Err(validator::ValidationError::new("password_missing_digit"));
    }
    if !has_special {
        return Err(validator::ValidationError::new("password_missing_special"));
    }

    Ok(())
}

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

    pub fn parse(s: &str) -> Self {
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
        AuthSource::parse(&self.auth_source)
    }
}

/// User creation request.
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct CreateUserRequest {
    #[validate(
        length(min = 3, max = 150, message = "Username must be 3-150 characters"),
        regex(path = "*RE_USERNAME", message = "Username contains invalid characters (use letters, numbers, dots, underscores, hyphens)")
    )]
    pub username: String,
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(custom(function = "validate_password_complexity"))]
    pub password: String,
    #[validate(length(max = 150, message = "First name too long"))]
    pub first_name: Option<String>,
    #[validate(length(max = 150, message = "Last name too long"))]
    pub last_name: Option<String>,
    #[validate(length(max = 20, message = "Phone number too long"))]
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
    use crate::unwrap_ok;
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
        assert_eq!(AuthSource::parse("local"), AuthSource::Local);
    }

    #[test]
    fn test_auth_source_from_str_ldap() {
        assert_eq!(AuthSource::parse("ldap"), AuthSource::Ldap);
    }

    #[test]
    fn test_auth_source_from_str_oidc() {
        assert_eq!(AuthSource::parse("oidc"), AuthSource::Oidc);
    }

    #[test]
    fn test_auth_source_from_str_saml() {
        assert_eq!(AuthSource::parse("saml"), AuthSource::Saml);
    }

    #[test]
    fn test_auth_source_from_str_unknown() {
        // Unknown values default to Local
        assert_eq!(AuthSource::parse("unknown"), AuthSource::Local);
        assert_eq!(AuthSource::parse(""), AuthSource::Local);
        assert_eq!(AuthSource::parse("LDAP"), AuthSource::Local); // Case sensitive
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
            let parsed = AuthSource::parse(str_val);
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
        let dto_json = unwrap_ok!(serde_json::to_value(&dto));
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

    // ==================== AuthSource Additional Tests ====================

    #[test]
    fn test_auth_source_debug() {
        let source = AuthSource::Local;
        let debug_str = format!("{:?}", source);
        assert!(debug_str.contains("Local"));
    }

    #[test]
    fn test_auth_source_clone() {
        let source = AuthSource::Ldap;
        let cloned = source.clone();
        assert_eq!(source, cloned);
    }

    #[test]
    fn test_auth_source_copy() {
        let source = AuthSource::Oidc;
        let copied = source;
        assert_eq!(source, copied);
    }

    #[test]
    fn test_auth_source_serialize() {
        let source = AuthSource::Saml;
        let json = unwrap_ok!(serde_json::to_string(&source));
        assert!(json.contains("Saml"));
    }

    #[test]
    fn test_auth_source_deserialize() {
        let json = r#""Local""#;
        let source: AuthSource = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(source, AuthSource::Local);
    }

    // ==================== User Additional Tests ====================

    #[test]
    fn test_user_clone() {
        let user = create_test_user();
        let cloned = user.clone();
        assert_eq!(user.uuid, cloned.uuid);
        assert_eq!(user.username, cloned.username);
    }

    #[test]
    fn test_user_debug() {
        let user = create_test_user();
        let debug_str = format!("{:?}", user);
        assert!(debug_str.contains("User"));
        assert!(debug_str.contains("testuser"));
    }

    #[test]
    fn test_user_to_dto_with_last_login_ip() {
        let mut user = create_test_user();
        user.last_login_ip = Some(unwrap_ok!("192.168.1.100/32".parse()));

        let dto = user.to_dto();
        // IpNetwork::to_string includes the CIDR notation
        assert_eq!(dto.last_login_ip, Some("192.168.1.100/32".to_string()));
    }

    #[test]
    fn test_user_to_dto_preserves_preferences() {
        let mut user = create_test_user();
        user.preferences = serde_json::json!({"theme": "dark", "language": "fr"});

        let dto = user.to_dto();
        assert_eq!(dto.preferences["theme"], "dark");
    }

    // ==================== UserDto Tests ====================

    #[test]
    fn test_user_dto_serialize() {
        let user = create_test_user();
        let dto = user.to_dto();
        let json = unwrap_ok!(serde_json::to_string(&dto));

        assert!(json.contains("testuser"));
        assert!(json.contains("test@example.com"));
    }

    #[test]
    fn test_user_dto_debug() {
        let user = create_test_user();
        let dto = user.to_dto();
        let debug_str = format!("{:?}", dto);

        assert!(debug_str.contains("UserDto"));
    }

    #[test]
    fn test_user_dto_clone() {
        let user = create_test_user();
        let dto = user.to_dto();
        let cloned = dto.clone();

        assert_eq!(dto.uuid, cloned.uuid);
    }

    // ==================== NewUser Tests ====================

    #[test]
    fn test_new_user_debug() {
        let new_user = NewUser {
            uuid: Uuid::new_v4(),
            username: "newuser".to_string(),
            email: "new@test.com".to_string(),
            password_hash: "hash".to_string(),
            first_name: None,
            last_name: None,
            phone: None,
            is_active: true,
            is_staff: false,
            is_superuser: false,
            is_service_account: false,
            mfa_enabled: false,
            mfa_enforced: false,
            mfa_secret: None,
            preferences: serde_json::json!({}),
            auth_source: "local".to_string(),
            external_id: None,
        };

        let debug_str = format!("{:?}", new_user);
        assert!(debug_str.contains("NewUser"));
    }

    #[test]
    fn test_new_user_clone() {
        let new_user = NewUser {
            uuid: Uuid::new_v4(),
            username: "cloneuser".to_string(),
            email: "clone@test.com".to_string(),
            password_hash: "hash".to_string(),
            first_name: Some("Clone".to_string()),
            last_name: Some("User".to_string()),
            phone: None,
            is_active: true,
            is_staff: true,
            is_superuser: false,
            is_service_account: false,
            mfa_enabled: false,
            mfa_enforced: false,
            mfa_secret: None,
            preferences: serde_json::json!({}),
            auth_source: "local".to_string(),
            external_id: None,
        };

        let cloned = new_user.clone();
        assert_eq!(new_user.username, cloned.username);
    }

    // ==================== UserUpdate Tests ====================

    #[test]
    fn test_user_update_debug() {
        let update = UserUpdate {
            email: Some("updated@test.com".to_string()),
            first_name: None,
            last_name: None,
            phone: None,
            is_active: None,
            preferences: None,
            updated_at: Utc::now(),
        };

        let debug_str = format!("{:?}", update);
        assert!(debug_str.contains("UserUpdate"));
    }

    #[test]
    fn test_user_update_clone() {
        let update = UserUpdate {
            email: Some("test@test.com".to_string()),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            phone: Some("+1234567890".to_string()),
            is_active: Some(true),
            preferences: Some(serde_json::json!({"key": "value"})),
            updated_at: Utc::now(),
        };

        let cloned = update.clone();
        assert_eq!(update.email, cloned.email);
    }

    // ==================== UpdateUserRequest Tests ====================

    #[test]
    fn test_update_user_request_debug() {
        let request = UpdateUserRequest {
            email: Some("debug@test.com".to_string()),
            first_name: None,
            last_name: None,
            phone: None,
            is_active: None,
            preferences: None,
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("UpdateUserRequest"));
    }

    #[test]
    fn test_update_user_request_clone() {
        let request = UpdateUserRequest {
            email: Some("clone@test.com".to_string()),
            first_name: Some("Clone".to_string()),
            last_name: None,
            phone: None,
            is_active: Some(false),
            preferences: None,
        };

        let cloned = request.clone();
        assert_eq!(request.email, cloned.email);
    }

    #[test]
    fn test_update_user_request_long_first_name_invalid() {
        use validator::Validate;

        let request = UpdateUserRequest {
            email: None,
            first_name: Some("A".repeat(151)), // Too long
            last_name: None,
            phone: None,
            is_active: None,
            preferences: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_update_user_request_long_phone_invalid() {
        use validator::Validate;

        let request = UpdateUserRequest {
            email: None,
            first_name: None,
            last_name: None,
            phone: Some("1".repeat(21)), // Too long
            is_active: None,
            preferences: None,
        };

        assert!(request.validate().is_err());
    }

    // ==================== CreateUserRequest Additional Tests ====================

    #[test]
    fn test_create_user_request_debug() {
        let request = CreateUserRequest {
            username: "debuguser".to_string(),
            email: "debug@example.com".to_string(),
            password: "securepassword123".to_string(),
            first_name: None,
            last_name: None,
            phone: None,
            is_staff: None,
            is_superuser: None,
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("CreateUserRequest"));
    }

    #[test]
    fn test_create_user_request_clone() {
        let request = CreateUserRequest {
            username: "cloneuser".to_string(),
            email: "clone@example.com".to_string(),
            password: "securepassword123".to_string(),
            first_name: Some("Clone".to_string()),
            last_name: None,
            phone: None,
            is_staff: Some(true),
            is_superuser: None,
        };

        let cloned = request.clone();
        assert_eq!(request.username, cloned.username);
    }

    #[test]
    fn test_create_user_request_long_username_invalid() {
        use validator::Validate;

        let request = CreateUserRequest {
            username: "a".repeat(151), // Too long
            email: "valid@example.com".to_string(),
            password: "securepassword123".to_string(),
            first_name: None,
            last_name: None,
            phone: None,
            is_staff: None,
            is_superuser: None,
        };

        assert!(request.validate().is_err());
    }
}
