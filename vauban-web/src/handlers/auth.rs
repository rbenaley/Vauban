/// VAUBAN Web - Authentication handlers.
///
/// Login, logout, MFA setup and verification.

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::user::User;
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
        .build();

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
        .build();

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

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== LoginRequest Tests ====================

    #[test]
    fn test_login_request_valid() {
        let request = LoginRequest {
            username: "validuser".to_string(),
            password: "validpassword123".to_string(),
            mfa_code: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_login_request_short_username() {
        let request = LoginRequest {
            username: "ab".to_string(), // Too short (min 3)
            password: "validpassword123".to_string(),
            mfa_code: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_login_request_short_password() {
        let request = LoginRequest {
            username: "validuser".to_string(),
            password: "short".to_string(), // Too short (min 12)
            mfa_code: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_login_request_with_mfa_code() {
        let request = LoginRequest {
            username: "validuser".to_string(),
            password: "validpassword123".to_string(),
            mfa_code: Some("123456".to_string()),
        };

        assert!(request.validate().is_ok());
        assert!(request.mfa_code.is_some());
    }

    #[test]
    fn test_login_request_username_minimum_length() {
        let request = LoginRequest {
            username: "abc".to_string(), // Exactly 3 chars
            password: "validpassword123".to_string(),
            mfa_code: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_login_request_password_minimum_length() {
        let request = LoginRequest {
            username: "validuser".to_string(),
            password: "123456789012".to_string(), // Exactly 12 chars
            mfa_code: None,
        };

        assert!(request.validate().is_ok());
    }

    // ==================== LoginResponse Tests ====================

    #[test]
    fn test_login_response_serialize() {
        let user_dto = crate::models::user::UserDto {
            uuid: ::uuid::Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            phone: None,
            is_active: true,
            is_staff: false,
            is_superuser: false,
            is_service_account: false,
            mfa_enabled: false,
            mfa_enforced: false,
            preferences: serde_json::json!({}),
            last_login: None,
            last_login_ip: None,
            auth_source: "local".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let response = LoginResponse {
            access_token: "token123".to_string(),
            refresh_token: "refresh456".to_string(),
            user: user_dto,
            mfa_required: false,
        };

        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("token123"));
        assert!(json.contains("refresh456"));
        assert!(json.contains("testuser"));
        assert!(json.contains("mfa_required"));
    }

    #[test]
    fn test_login_response_mfa_required() {
        let user_dto = crate::models::user::UserDto {
            uuid: ::uuid::Uuid::new_v4(),
            username: "mfauser".to_string(),
            email: "mfa@example.com".to_string(),
            first_name: None,
            last_name: None,
            phone: None,
            is_active: true,
            is_staff: false,
            is_superuser: false,
            is_service_account: false,
            mfa_enabled: true,
            mfa_enforced: true,
            preferences: serde_json::json!({}),
            last_login: None,
            last_login_ip: None,
            auth_source: "local".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let response = LoginResponse {
            access_token: String::new(),
            refresh_token: String::new(),
            user: user_dto,
            mfa_required: true,
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["mfa_required"], true);
    }

    // ==================== MfaSetupResponse Tests ====================

    #[test]
    fn test_mfa_setup_response_serialize() {
        let response = MfaSetupResponse {
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            qr_code_url: "otpauth://totp/VAUBAN:testuser".to_string(),
            qr_code_base64: Some("base64data...".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("JBSWY3DPEHPK3PXP"));
        assert!(json.contains("otpauth://"));
        assert!(json.contains("qr_code_base64"));
    }

    #[test]
    fn test_mfa_setup_response_without_qr_code() {
        let response = MfaSetupResponse {
            secret: "TESTSECRET".to_string(),
            qr_code_url: "otpauth://totp/TEST:user".to_string(),
            qr_code_base64: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed["qr_code_base64"].is_null());
    }
}

