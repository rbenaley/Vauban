/// VAUBAN Web - Authentication handlers.
///
/// Login, logout, MFA setup and verification.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::user::{User, NewUser, CreateUserRequest, UserDto};
use crate::schema::users::dsl::*;
use crate::services::auth::AuthService;
use crate::AppState;
use crate::db::get_connection;
use diesel::prelude::*;

/// Login request.
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 3))]
    pub username: String,
    #[validate(length(min = 12))]
    pub password: String,
    pub mfa_code: Option<String>,
}

/// Login response.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: crate::models::user::UserDto,
    pub mfa_required: bool,
}

/// Login handler.
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> AppResult<Response> {
    validator::Validate::validate(&request).map_err(|e| {
        AppError::Validation(format!("Validation failed: {:?}", e))
    })?;

    let mut conn = get_connection(&state.db_pool)?;

    // Find user by username
    let user = users
        .filter(username.eq(&request.username))
        .filter(is_deleted.eq(false))
        .first::<User>(&mut conn)
        .optional()
        .map_err(|e| AppError::Database(e))?
        .ok_or_else(|| AppError::Auth("Invalid credentials".to_string()))?;

    // Check if account is locked
    if user.is_locked() {
        return Err(AppError::Auth("Account is locked".to_string()));
    }

    // Verify password
    let password_valid = state.auth_service.verify_password(&request.password, &user.password_hash)?;
    if !password_valid {
        // Increment failed attempts
        diesel::update(users.find(user.id))
            .set(failed_login_attempts.eq(failed_login_attempts + 1))
            .execute(&mut conn)
            .map_err(|e| AppError::Database(e))?;
        return Err(AppError::Auth("Invalid credentials".to_string()));
    }

    // Check MFA
    let mfa_verified = if user.mfa_enabled {
        if let Some(code) = request.mfa_code {
            if let Some(secret) = &user.mfa_secret {
                AuthService::verify_totp(secret, &code)
            } else {
                false
            }
        } else {
            return Ok(Json(LoginResponse {
                access_token: String::new(),
                refresh_token: String::new(),
                user: user.to_dto(),
                mfa_required: true,
            })
            .into_response());
        }
    } else {
        true
    };

    // Generate tokens
    let access_token = state.auth_service.generate_access_token(
        &user.uuid.to_string(),
        &user.username,
        mfa_verified,
        user.is_superuser,
        user.is_staff,
    )?;

    // Reset failed attempts and update last_login
    diesel::update(users.find(user.id))
        .set((
            failed_login_attempts.eq(0),
            locked_until.eq(None::<chrono::DateTime<chrono::Utc>>),
            last_login.eq(chrono::Utc::now()),
        ))
        .execute(&mut conn)
        .map_err(|e| AppError::Database(e))?;

    let response = LoginResponse {
        access_token: access_token.clone(),
        refresh_token: String::new(), // TODO: Implement refresh tokens
        user: user.to_dto(),
        mfa_required: false,
    };

    // Set cookie
    use axum_extra::extract::cookie::{Cookie, SameSite};
    let cookie = Cookie::build(("access_token", access_token))
        .path("/")
        .http_only(true)
        .secure(false) // Set to true in production with HTTPS
        .same_site(SameSite::Lax) // Changed to Lax for better compatibility
        .finish();

    Ok((jar.add(cookie), Json(response)).into_response())
}

/// Logout handler.
pub async fn logout(jar: CookieJar) -> Response {
    use axum_extra::extract::cookie::Cookie;
    use time::Duration;
    use axum::response::Redirect;
    
    let cookie = Cookie::build(("access_token", ""))
        .path("/")
        .http_only(true)
        .max_age(Duration::ZERO)
        .finish();

    (jar.add(cookie), Redirect::to("/login")).into_response()
}

/// MFA setup request.
#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    pub secret: String,
    pub qr_code_url: String,
    pub qr_code_base64: Option<String>,
}

/// Setup MFA handler.
pub async fn setup_mfa(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<MfaSetupResponse>> {
    // Generate TOTP secret with provisioning URI
    let (secret, qr_code_url) = AuthService::generate_totp_secret(&user.username, "VAUBAN")?;

    // Generate QR code as base64 PNG for direct embedding
    let qr_code_base64 = AuthService::generate_totp_qr_code(&secret, &user.username, "VAUBAN").ok();

    // Save secret to database
    let mut conn = get_connection(&state.db_pool)?;
    use ::uuid::Uuid as UuidType;
    let user_uuid = UuidType::parse_str(&user.uuid).map_err(|_| {
        AppError::Validation("Invalid user UUID".to_string())
    })?;
    diesel::update(users.filter(uuid.eq(user_uuid)))
    .set(mfa_secret.eq(Some(secret.clone())))
    .execute(&mut conn)
    .map_err(|e| AppError::Database(e))?;

    Ok(Json(MfaSetupResponse {
        secret,
        qr_code_url,
        qr_code_base64,
    }))
}

