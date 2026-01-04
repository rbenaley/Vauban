/// VAUBAN Web - Authentication handlers.
///
/// Login, logout, MFA setup and verification.

use axum::{
    extract::State,
    http::{header::HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Response},
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

/// Check if request is from HTMX (has HX-Request header)
fn is_htmx_request(headers: &HeaderMap) -> bool {
    headers.get("HX-Request").is_some()
}

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
/// Supports both JSON API and HTMX requests.
/// For HTMX: returns HTML fragments and HX-Redirect header on success.
/// For JSON: returns LoginResponse as before.
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> AppResult<Response> {
    let htmx = is_htmx_request(&headers);
    
    // Validation
    if let Err(e) = validator::Validate::validate(&request) {
        if htmx {
            return Ok(Html(format!(
                r#"<div id="login-result" class="rounded-md bg-red-50 dark:bg-red-900/50 p-4">
                    <p class="text-sm font-medium text-red-800 dark:text-red-200">Validation error: {}</p>
                </div>"#,
                e
            )).into_response());
        }
        return Err(AppError::Validation(format!("Validation failed: {:?}", e)));
    }

    let mut conn = get_connection(&state.db_pool)?;

    // Find user by username
    let user = match users
        .filter(username.eq(&request.username))
        .filter(is_deleted.eq(false))
        .first::<User>(&mut conn)
        .optional()
        .map_err(|e| AppError::Database(e))?
    {
        Some(u) => u,
        None => {
            if htmx {
                return Ok(Html(login_error_html("Invalid credentials")).into_response());
            }
            return Err(AppError::Auth("Invalid credentials".to_string()));
        }
    };

    // Check if account is locked
    if user.is_locked() {
        if htmx {
            return Ok(Html(login_error_html("Account is locked")).into_response());
        }
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
        
        if htmx {
            return Ok(Html(login_error_html("Invalid credentials")).into_response());
        }
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
            // MFA required - for HTMX, reveal MFA section
            if htmx {
                return Ok(Html(login_mfa_required_html()).into_response());
            }
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

    if user.mfa_enabled && !mfa_verified {
        if htmx {
            return Ok(Html(login_error_html("Invalid MFA code")).into_response());
        }
        return Err(AppError::Auth("Invalid MFA code".to_string()));
    }

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

    // Set cookie
    use axum_extra::extract::cookie::{Cookie, SameSite};
    let cookie = Cookie::build(("access_token", access_token.clone()))
        .path("/")
        .http_only(true)
        .secure(false) // Set to true in production with HTTPS
        .same_site(SameSite::Lax) // Changed to Lax for better compatibility
        .build();

    // For HTMX: return redirect header
    if htmx {
        let mut response = Html("").into_response();
        response.headers_mut().insert(
            "HX-Redirect",
            HeaderValue::from_static("/dashboard"),
        );
        return Ok((jar.add(cookie), response).into_response());
    }

    // For JSON API
    let response = LoginResponse {
        access_token,
        refresh_token: String::new(), // TODO: Implement refresh tokens
        user: user.to_dto(),
        mfa_required: false,
    };

    Ok((jar.add(cookie), Json(response)).into_response())
}

/// Generate error HTML for HTMX login response.
fn login_error_html(message: &str) -> String {
    format!(
        r#"<div id="login-result" class="rounded-md bg-red-50 dark:bg-red-900/50 p-4">
            <div class="flex">
                <div class="flex-shrink-0">
                    <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                    </svg>
                </div>
                <div class="ml-3">
                    <p class="text-sm font-medium text-red-800 dark:text-red-200">{}</p>
                </div>
            </div>
        </div>"#,
        message
    )
}

/// Generate MFA required HTML for HTMX login response.
fn login_mfa_required_html() -> String {
    r#"<div id="login-result"></div>
    <div id="mfa-section" hx-swap-oob="outerHTML:#mfa-section" class="space-y-4">
        <div>
            <label for="mfa_code" class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                MFA Code
            </label>
            <input id="mfa_code" name="mfa_code" type="text"
                   class="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white rounded-md focus:outline-none focus:ring-vauban-500 focus:border-vauban-500 focus:z-10 sm:text-sm dark:bg-gray-700"
                   placeholder="000000" autocomplete="one-time-code" autofocus>
        </div>
        <p class="text-sm text-gray-600 dark:text-gray-400">Enter the code from your authenticator app.</p>
    </div>"#.to_string()
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

