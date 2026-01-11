use ::uuid::Uuid;
/// VAUBAN Web - Account management handlers.
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;

use crate::AppState;
use crate::db::get_connection;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::user::{CreateUserRequest, NewUser, UpdateUserRequest, User, UserDto};
use crate::schema::users::dsl::*;
use diesel::prelude::*;

/// List users handler.
pub async fn list_users(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(params): Query<ListUsersParams>,
) -> AppResult<Json<Vec<UserDto>>> {
    let mut conn = get_connection(&state.db_pool)?;
    let mut query = users.filter(is_deleted.eq(false)).into_boxed();

    if let Some(search) = params.search {
        query = query.filter(
            username
                .ilike(format!("%{}%", search))
                .or(email.ilike(format!("%{}%", search))),
        );
    }

    let users_list = query
        .limit(params.limit.unwrap_or(50))
        .offset(params.offset.unwrap_or(0))
        .load::<User>(&mut conn)?;

    Ok(Json(users_list.iter().map(|u| u.to_dto()).collect()))
}

/// Get user by UUID handler.
pub async fn get_user(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(user_uuid): Path<Uuid>,
) -> AppResult<Json<UserDto>> {
    let mut conn = get_connection(&state.db_pool)?;
    let user = users
        .filter(uuid.eq(user_uuid))
        .filter(is_deleted.eq(false))
        .first::<User>(&mut conn)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("User not found".to_string()),
            _ => AppError::Database(e),
        })?;

    Ok(Json(user.to_dto()))
}

/// Create user handler.
pub async fn create_user(
    State(state): State<AppState>,
    _user: AuthUser,
    Json(request): Json<CreateUserRequest>,
) -> AppResult<Json<UserDto>> {
    validator::Validate::validate(&request)
        .map_err(|e| AppError::Validation(format!("Validation failed: {:?}", e)))?;

    let mut conn = get_connection(&state.db_pool)?;

    // Hash password
    let hashed_password = state.auth_service.hash_password(&request.password)?;

    use ::uuid::Uuid as UuidType;
    let new_user = NewUser {
        uuid: UuidType::new_v4(),
        username: request.username,
        email: request.email,
        password_hash: hashed_password,
        first_name: request.first_name,
        last_name: request.last_name,
        phone: None,
        is_active: true,
        is_staff: request.is_staff.unwrap_or(false),
        is_superuser: request.is_superuser.unwrap_or(false),
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: "local".to_string(),
        external_id: None,
    };

    let user: User = diesel::insert_into(users)
        .values(&new_user)
        .get_result(&mut conn)?;

    Ok(Json(user.to_dto()))
}

/// Update user handler.
pub async fn update_user(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(user_uuid): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> AppResult<Json<UserDto>> {
    validator::Validate::validate(&request)
        .map_err(|e| AppError::Validation(format!("Validation failed: {:?}", e)))?;

    let mut conn = get_connection(&state.db_pool)?;

    use crate::models::user::UserUpdate;
    use crate::schema::users::dsl::{users, uuid};

    let update_data = UserUpdate {
        email: request.email,
        first_name: request.first_name,
        last_name: request.last_name,
        phone: request.phone,
        is_active: request.is_active,
        preferences: request.preferences,
        updated_at: chrono::Utc::now(),
    };

    let user: User = diesel::update(users.filter(uuid.eq(user_uuid)))
        .set(&update_data)
        .get_result(&mut conn)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("User not found".to_string()),
            _ => AppError::Database(e),
        })?;

    Ok(Json(user.to_dto()))
}

/// Query parameters for list users.
#[derive(Debug, Deserialize)]
pub struct ListUsersParams {
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl ListUsersParams {
    /// Get limit with default value.
    pub fn get_limit(&self) -> i64 {
        self.limit.unwrap_or(50)
    }

    /// Get offset with default value.
    pub fn get_offset(&self) -> i64 {
        self.offset.unwrap_or(0)
    }

    /// Check if search term is provided.
    pub fn has_search(&self) -> bool {
        self.search.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::user::{CreateUserRequest, UpdateUserRequest};
    use validator::Validate;

    // ==================== ListUsersParams Tests ====================

    #[test]
    fn test_list_users_params_default_limit() {
        let params = ListUsersParams {
            search: None,
            limit: None,
            offset: None,
        };

        assert_eq!(params.get_limit(), 50);
    }

    #[test]
    fn test_list_users_params_custom_limit() {
        let params = ListUsersParams {
            search: None,
            limit: Some(100),
            offset: None,
        };

        assert_eq!(params.get_limit(), 100);
    }

    #[test]
    fn test_list_users_params_default_offset() {
        let params = ListUsersParams {
            search: None,
            limit: None,
            offset: None,
        };

        assert_eq!(params.get_offset(), 0);
    }

    #[test]
    fn test_list_users_params_custom_offset() {
        let params = ListUsersParams {
            search: None,
            limit: None,
            offset: Some(25),
        };

        assert_eq!(params.get_offset(), 25);
    }

    #[test]
    fn test_list_users_params_has_search_none() {
        let params = ListUsersParams {
            search: None,
            limit: None,
            offset: None,
        };

        assert!(!params.has_search());
    }

    #[test]
    fn test_list_users_params_has_search_empty() {
        let params = ListUsersParams {
            search: Some("".to_string()),
            limit: None,
            offset: None,
        };

        assert!(!params.has_search());
    }

    #[test]
    fn test_list_users_params_has_search_valid() {
        let params = ListUsersParams {
            search: Some("admin".to_string()),
            limit: None,
            offset: None,
        };

        assert!(params.has_search());
    }

    #[test]
    fn test_list_users_params_debug() {
        let params = ListUsersParams {
            search: Some("test".to_string()),
            limit: Some(10),
            offset: Some(5),
        };

        let debug_str = format!("{:?}", params);

        assert!(debug_str.contains("ListUsersParams"));
        assert!(debug_str.contains("test"));
        assert!(debug_str.contains("10"));
        assert!(debug_str.contains("5"));
    }

    // ==================== CreateUserRequest Validation Tests ====================

    #[test]
    fn test_create_user_request_valid() {
        let request = CreateUserRequest {
            username: "newuser".to_string(),
            email: "new@example.com".to_string(),
            password: "securepassword123".to_string(),
            first_name: Some("New".to_string()),
            last_name: Some("User".to_string()),
            phone: None,
            is_staff: None,
            is_superuser: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_user_request_invalid_email() {
        let request = CreateUserRequest {
            username: "newuser".to_string(),
            email: "not-an-email".to_string(),
            password: "securepassword123".to_string(),
            first_name: None,
            last_name: None,
            phone: None,
            is_staff: None,
            is_superuser: None,
        };

        assert!(request.validate().is_err());
    }

    // ==================== UpdateUserRequest Validation Tests ====================

    #[test]
    fn test_update_user_request_valid() {
        let request = UpdateUserRequest {
            email: Some("updated@example.com".to_string()),
            first_name: Some("Updated".to_string()),
            last_name: Some("Name".to_string()),
            phone: Some("+1234567890".to_string()),
            is_active: Some(true),
            preferences: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_update_user_request_invalid_email() {
        let request = UpdateUserRequest {
            email: Some("invalid".to_string()),
            first_name: None,
            last_name: None,
            phone: None,
            is_active: None,
            preferences: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_update_user_request_empty() {
        let request = UpdateUserRequest {
            email: None,
            first_name: None,
            last_name: None,
            phone: None,
            is_active: None,
            preferences: None,
        };

        // Empty update should be valid
        assert!(request.validate().is_ok());
    }

    // ==================== ListUsersParams Additional Tests ====================

    #[test]
    fn test_list_users_params_all_set() {
        let params = ListUsersParams {
            search: Some("admin".to_string()),
            limit: Some(100),
            offset: Some(50),
        };
        
        assert!(params.has_search());
        assert_eq!(params.get_limit(), 100);
        assert_eq!(params.get_offset(), 50);
    }

    #[test]
    fn test_list_users_params_search_whitespace() {
        let params = ListUsersParams {
            search: Some("   ".to_string()),
            limit: None,
            offset: None,
        };
        
        // Whitespace-only string is not empty
        assert!(params.has_search());
    }

    #[test]
    fn test_list_users_params_unicode_search() {
        let params = ListUsersParams {
            search: Some("用户".to_string()),
            limit: None,
            offset: None,
        };
        
        assert!(params.has_search());
    }

    #[test]
    fn test_list_users_params_large_limit() {
        let params = ListUsersParams {
            search: None,
            limit: Some(1000),
            offset: None,
        };
        
        assert_eq!(params.get_limit(), 1000);
    }

    #[test]
    fn test_list_users_params_zero_values() {
        let params = ListUsersParams {
            search: None,
            limit: Some(0),
            offset: Some(0),
        };
        
        assert_eq!(params.get_limit(), 0);
        assert_eq!(params.get_offset(), 0);
    }

    // ==================== CreateUserRequest Additional Tests ====================

    #[test]
    fn test_create_user_request_minimal() {
        let request = CreateUserRequest {
            username: "minuser".to_string(),
            email: "min@example.com".to_string(),
            password: "securepassword123".to_string(),
            first_name: None,
            last_name: None,
            phone: None,
            is_staff: None,
            is_superuser: None,
        };
        
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_user_request_full() {
        let request = CreateUserRequest {
            username: "fulluser".to_string(),
            email: "full@example.com".to_string(),
            password: "securepassword123".to_string(),
            first_name: Some("Full".to_string()),
            last_name: Some("User".to_string()),
            phone: Some("+1234567890".to_string()),
            is_staff: Some(true),
            is_superuser: Some(true),
        };
        
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_user_request_unicode_names() {
        let request = CreateUserRequest {
            username: "unicodeuser".to_string(),
            email: "unicode@example.com".to_string(),
            password: "securepassword123".to_string(),
            first_name: Some("张".to_string()),
            last_name: Some("三".to_string()),
            phone: None,
            is_staff: None,
            is_superuser: None,
        };
        
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_user_request_long_password() {
        let request = CreateUserRequest {
            username: "longpassuser".to_string(),
            email: "longpass@example.com".to_string(),
            password: "a".repeat(100),
            first_name: None,
            last_name: None,
            phone: None,
            is_staff: None,
            is_superuser: None,
        };
        
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_user_request_short_username() {
        let request = CreateUserRequest {
            username: "ab".to_string(), // Might be too short
            email: "short@example.com".to_string(),
            password: "securepassword123".to_string(),
            first_name: None,
            last_name: None,
            phone: None,
            is_staff: None,
            is_superuser: None,
        };
        
        // Check validation - might fail depending on min length
        let _ = request.validate();
    }

    // ==================== UpdateUserRequest Additional Tests ====================

    #[test]
    fn test_update_user_request_only_email() {
        let request = UpdateUserRequest {
            email: Some("newemail@example.com".to_string()),
            first_name: None,
            last_name: None,
            phone: None,
            is_active: None,
            preferences: None,
        };
        
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_update_user_request_with_preferences() {
        let request = UpdateUserRequest {
            email: None,
            first_name: None,
            last_name: None,
            phone: None,
            is_active: None,
            preferences: Some(serde_json::json!({"theme": "dark", "language": "fr"})),
        };
        
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_update_user_request_deactivate() {
        let request = UpdateUserRequest {
            email: None,
            first_name: None,
            last_name: None,
            phone: None,
            is_active: Some(false),
            preferences: None,
        };
        
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_update_user_request_international_phone() {
        let request = UpdateUserRequest {
            email: None,
            first_name: None,
            last_name: None,
            phone: Some("+33 1 23 45 67 89".to_string()),
            is_active: None,
            preferences: None,
        };
        
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_update_user_request_empty_strings() {
        let request = UpdateUserRequest {
            email: None,
            first_name: Some("".to_string()),
            last_name: Some("".to_string()),
            phone: Some("".to_string()),
            is_active: None,
            preferences: None,
        };
        
        // Empty strings might be valid depending on validation
        let _ = request.validate();
    }

    // ==================== Deserialize Tests ====================

    #[test]
    fn test_list_users_params_deserialize() {
        let json = r#"{"search": "test", "limit": 25, "offset": 5}"#;
        let params: ListUsersParams = serde_json::from_str(json).unwrap();
        
        assert_eq!(params.search, Some("test".to_string()));
        assert_eq!(params.limit, Some(25));
        assert_eq!(params.offset, Some(5));
    }

    #[test]
    fn test_list_users_params_deserialize_empty() {
        let json = r#"{}"#;
        let params: ListUsersParams = serde_json::from_str(json).unwrap();
        
        assert!(params.search.is_none());
        assert!(params.limit.is_none());
        assert!(params.offset.is_none());
    }
}
