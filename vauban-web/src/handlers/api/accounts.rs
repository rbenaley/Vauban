/// VAUBAN Web - Accounts API handlers.
///
/// JSON API handlers for user account management.
use ::uuid::Uuid;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use diesel::prelude::*;
use serde::Deserialize;

use crate::AppState;
use crate::db::get_connection;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::user::{CreateUserRequest, NewUser, UpdateUserRequest, User, UserDto};
use crate::schema::users::dsl::*;

/// Query parameters for list users.
#[derive(Debug, Deserialize)]
pub struct ListUsersParams {
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_users_params_defaults() {
        let params = ListUsersParams {
            search: None,
            limit: None,
            offset: None,
        };

        assert!(params.search.is_none());
        assert_eq!(params.limit.unwrap_or(50), 50);
        assert_eq!(params.offset.unwrap_or(0), 0);
    }
}
