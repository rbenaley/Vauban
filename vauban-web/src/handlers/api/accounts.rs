/// VAUBAN Web - Accounts API handlers.
///
/// JSON API handlers for user account management.
use ::uuid::Uuid;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::Deserialize;

use crate::AppState;
use crate::auth::PermissionContext;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::user::{
    AuthSource, CreateUserRequest, NewUser, UpdateUserRequest, User, UserDto,
};
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
    perms: PermissionContext,
    Query(params): Query<ListUsersParams>,
) -> AppResult<Json<Vec<UserDto>>> {
    if !perms.users_read {
        return Err(AppError::forbidden("users:read"));
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let mut query = users.filter(is_deleted.eq(false)).into_boxed();

    if let Some(search) = params.search {
        let pattern = crate::db::like_contains(&search);
        query = query.filter(username.ilike(pattern.clone()).or(email.ilike(pattern)));
    }

    let users_list = query
        .limit(params.limit.unwrap_or(50))
        .offset(params.offset.unwrap_or(0))
        .load::<User>(&mut conn)
        .await?;

    Ok(Json(users_list.iter().map(|u| u.to_dto()).collect()))
}

/// Get user by UUID handler.
pub async fn get_user(
    State(state): State<AppState>,
    _user: AuthUser,
    perms: PermissionContext,
    Path(user_uuid_str): Path<String>,
) -> AppResult<Json<UserDto>> {
    if !perms.users_read {
        return Err(AppError::forbidden("users:read"));
    }

    // Parse UUID manually for better error messages
    let user_uuid = Uuid::parse_str(&user_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let user = users
        .filter(uuid.eq(user_uuid))
        .filter(is_deleted.eq(false))
        .first::<User>(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("User not found".to_string()),
            _ => AppError::Database(e),
        })?;

    Ok(Json(user.to_dto()))
}

/// Strip ALL HTML tags from an optional string to prevent stored XSS.
/// Uses ammonia with an empty tag allowlist so every tag is removed.
fn sanitize_text(value: Option<String>) -> Option<String> {
    value.map(|s| {
        ammonia::Builder::new()
            .tags(std::collections::HashSet::new())
            .clean(&s)
            .to_string()
    })
}

/// Create user handler.
///
/// Requires `users:write` for any account creation. Promoting the new
/// account to superuser additionally requires `users:manage_admins`,
/// preventing staff from escalating privileges by going through the API.
pub async fn create_user(
    State(state): State<AppState>,
    _user: AuthUser,
    perms: PermissionContext,
    Json(mut request): Json<CreateUserRequest>,
) -> AppResult<Json<UserDto>> {
    if !perms.users_write {
        return Err(AppError::forbidden("users:write"));
    }
    if request.is_superuser.unwrap_or(false) && !perms.users_manage_admins {
        return Err(AppError::forbidden("users:manage_admins"));
    }

    validator::Validate::validate(&request)
        .map_err(|e| AppError::Validation(format!("Validation failed: {:?}", e)))?;

    // Canonicalise the identity to its case-insensitive form so logins
    // match regardless of the casing typed at creation, and so the
    // DB-level `lower(username)` unique index treats `Alice`/`alice` as
    // one account. Validation runs first on the raw input (the regex
    // accepts mixed case); normalization happens after.
    request.username = shared::username::normalize_username(&request.username);

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let hashed_password = if let Some(ref client) = state.auth_ipc_client {
        client.hash_password(&request.password).await?
    } else {
        state.auth_service.hash_password(&request.password)?
    };

    // Sanitize text fields to prevent XSS
    let sanitized_first_name = sanitize_text(request.first_name);
    let sanitized_last_name = sanitize_text(request.last_name);

    use ::uuid::Uuid as UuidType;
    let new_user = NewUser {
        uuid: UuidType::new_v4(),
        username: request.username,
        email: request.email,
        password_hash: hashed_password,
        first_name: sanitized_first_name,
        last_name: sanitized_last_name,
        phone: None,
        is_active: true,
        is_staff: request.is_staff.unwrap_or(false),
        is_superuser: request.is_superuser.unwrap_or(false),
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: AuthSource::Local,
        external_id: None,
    };

    let user: User = diesel::insert_into(users)
        .values(&new_user)
        .get_result(&mut conn)
        .await?;

    Ok(Json(user.to_dto()))
}

/// Update user handler.
///
/// Role-invariant fence (see [`crate::services::role_invariants`]):
///
/// * **Self-deactivate** is refused up-front. The JSON API does not
///   expose `is_superuser`/`is_staff`, so self-demotion of those flags
///   is structurally impossible here, but `is_active=false` on the
///   operator's own row would be an instant lock-out and is rejected
///   with HTTP 403.
/// * **Last-active-superuser deactivate** is enforced inside a
///   SERIALIZABLE transaction wrapping the in-tx snapshot read,
///   [`check_last_active_superuser`] and the `UPDATE`. Two concurrent
///   `is_active=false` calls targeting the last two superusers cannot
///   both succeed.
pub async fn update_user(
    State(state): State<AppState>,
    auth_user: AuthUser,
    perms: PermissionContext,
    Path(user_uuid_str): Path<String>,
    Json(request): Json<UpdateUserRequest>,
) -> AppResult<Json<UserDto>> {
    use crate::services::role_invariants::{
        ChangeIntent, CheckError, RoleSnapshot, check_last_active_superuser, check_self_change,
        run_serializable,
    };

    if !perms.users_write {
        return Err(AppError::forbidden("users:write"));
    }

    // Parse UUID manually for better error messages
    let user_uuid = Uuid::parse_str(&user_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    let operator_uuid = Uuid::parse_str(&auth_user.uuid)
        .map_err(|_| AppError::Validation("Invalid session".to_string()))?;

    validator::Validate::validate(&request)
        .map_err(|e| AppError::Validation(format!("Validation failed: {:?}", e)))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    use crate::models::user::UserUpdate;
    use crate::schema::users::dsl::{users, uuid};

    // Load full role snapshot to detect changes (SEC-07) AND drive the
    // role-invariant fence below.
    let (target_user_id, old_is_super, old_is_staff, old_is_active): (i32, bool, bool, bool) =
        users
            .filter(uuid.eq(user_uuid))
            .select((
                crate::schema::users::id,
                crate::schema::users::is_superuser,
                crate::schema::users::is_staff,
                crate::schema::users::is_active,
            ))
            .first(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::NotFound => AppError::NotFound("User not found".to_string()),
                _ => AppError::Database(e),
            })?;

    // Sanitize text fields to prevent XSS
    let sanitized_first_name = sanitize_text(request.first_name);
    let sanitized_last_name = sanitize_text(request.last_name);

    let new_is_active = request.is_active;

    // Self-change check: the API only exposes `is_active`, but a self
    // `is_active=false` would be a lock-out so we refuse it up-front.
    let before = RoleSnapshot {
        is_superuser: old_is_super,
        is_staff: old_is_staff,
        is_active: old_is_active,
        is_deleted: false,
    };
    let after = RoleSnapshot {
        is_superuser: old_is_super,
        is_staff: old_is_staff,
        is_active: new_is_active.unwrap_or(old_is_active),
        is_deleted: false,
    };
    if let Err(violation) = check_self_change(operator_uuid, user_uuid, &before, &after, false) {
        tracing::info!(
            operator = %auth_user.uuid,
            target = %user_uuid_str,
            violation = ?violation,
            "api::update_user: refused self-mutation"
        );
        return Err(AppError::Authorization(
            violation.flash_message().to_string(),
        ));
    }

    // Drop the pre-tx connection before entering `run_serializable` so
    // the pool is not pinned with two checkouts at once.
    drop(conn);

    let pool_ref = &state.db_pool;
    // Locals named to avoid clashing with the `users::dsl::*` glob
    // imported at the top of this file (which brings the column tokens
    // `email`, `phone`, `preferences`, etc. into scope and would
    // shadow our values otherwise).
    let req_email = request.email.clone();
    let req_phone = request.phone.clone();
    let req_preferences = request.preferences.clone();
    let req_email_ref = &req_email;
    let req_first_name_ref = &sanitized_first_name;
    let req_last_name_ref = &sanitized_last_name;
    let req_phone_ref = &req_phone;
    let req_preferences_ref = &req_preferences;

    let updated_user = run_serializable::<User, _>(pool_ref, move |c| {
        let email_clone = req_email_ref.clone();
        let first_name_clone = req_first_name_ref.clone();
        let last_name_clone = req_last_name_ref.clone();
        let phone_clone = req_phone_ref.clone();
        let preferences_clone = req_preferences_ref.clone();
        Box::pin(async move {
            // Re-read the target inside the SERIALIZABLE snapshot.
            let row: Option<(i32, bool, bool, bool)> = users
                .filter(uuid.eq(user_uuid))
                .select((
                    crate::schema::users::id,
                    crate::schema::users::is_superuser,
                    crate::schema::users::is_staff,
                    crate::schema::users::is_active,
                ))
                .first(c)
                .await
                .optional()
                .map_err(CheckError::Db)?;
            let (in_tx_id, b_super, b_staff, b_active) = match row {
                Some(t) => t,
                None => {
                    return Err(CheckError::Db(diesel::result::Error::NotFound));
                }
            };
            let in_tx_before = RoleSnapshot {
                is_superuser: b_super,
                is_staff: b_staff,
                is_active: b_active,
                is_deleted: false,
            };

            // Last-active-superuser fence on `is_active=false` only.
            // The API does not flip `is_superuser`, so `Deactivate` is
            // the only relevant intent here.
            if let Some(false) = new_is_active
                && in_tx_before.is_superuser
                && in_tx_before.is_active
            {
                check_last_active_superuser(c, in_tx_id, &in_tx_before, ChangeIntent::Deactivate)
                    .await?;
            }

            let update_data = UserUpdate {
                email: email_clone,
                first_name: first_name_clone,
                last_name: last_name_clone,
                phone: phone_clone,
                is_active: new_is_active,
                preferences: preferences_clone,
                updated_at: chrono::Utc::now(),
            };

            let updated: User = diesel::update(users.filter(uuid.eq(user_uuid)))
                .set(&update_data)
                .get_result(c)
                .await
                .map_err(CheckError::Db)?;
            Ok(updated)
        })
    })
    .await
    .map_err(|e| match e {
        CheckError::Violation(v) => AppError::Authorization(v.flash_message().to_string()),
        CheckError::Db(diesel::result::Error::NotFound) => {
            AppError::NotFound("User not found".to_string())
        }
        CheckError::Db(e) => AppError::Database(e),
    })?;

    // Trigger side effects on is_active change (SEC-07). Same rationale
    // as `update_user_web`: best-effort, post-commit, kept out of the
    // SERIALIZABLE tx to bound its lock window.
    if let Some(new_active) = new_is_active {
        if old_is_active && !new_active {
            crate::handlers::web::deactivate_user(&state, target_user_id, &user_uuid_str).await;
        } else if !old_is_active && new_active {
            crate::handlers::web::reactivate_user(&state, target_user_id).await;
        }
    }

    Ok(Json(updated_user.to_dto()))
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
