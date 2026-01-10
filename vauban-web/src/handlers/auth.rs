/// VAUBAN Web - Authentication handlers.
///
/// Login, logout, MFA setup and verification.
use axum::{
    Json,
    extract::State,
    http::{HeaderValue, header::HeaderMap},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::net::SocketAddr;
use validator::Validate;

use crate::AppState;
use crate::db::get_connection;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::auth_session::{AuthSession, NewAuthSession};
use crate::models::user::User;
use crate::schema::{auth_sessions, users::dsl::*};
use crate::services::auth::AuthService;

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
    // Default client address for when ConnectInfo is not available (tests)
    let client_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
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
    let password_valid = state
        .auth_service
        .verify_password(&request.password, &user.password_hash)?;
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

    // Create auth session record for session management
    let token_hash = hash_token(&access_token);
    let client_ip = extract_client_ip(&headers, client_addr);
    let user_agent_str = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let device_info = user_agent_str
        .as_ref()
        .map(|ua| AuthSession::parse_device_info(ua));

    // Mark any existing "current" sessions as not current
    diesel::update(
        auth_sessions::table
            .filter(auth_sessions::user_id.eq(user.id))
            .filter(auth_sessions::is_current.eq(true)),
    )
    .set(auth_sessions::is_current.eq(false))
    .execute(&mut conn)
    .ok(); // Ignore errors - not critical

    // Insert new session
    let new_session = NewAuthSession {
        uuid: ::uuid::Uuid::new_v4(),
        user_id: user.id,
        token_hash,
        ip_address: client_ip,
        user_agent: user_agent_str,
        device_info,
        expires_at: Utc::now() + Duration::minutes(state.auth_service.access_token_lifetime_minutes() as i64),
        is_current: true,
    };

    let session_created = diesel::insert_into(auth_sessions::table)
        .values(&new_session)
        .execute(&mut conn)
        .map_err(|e| {
            tracing::warn!("Failed to create auth session: {}", e);
            e
        })
        .is_ok();

    // Broadcast session update to all connected WebSocket clients for this user
    if session_created {
        crate::handlers::web::broadcast_sessions_update(
            &state,
            &user.uuid.to_string(),
            user.id,
        )
        .await;
    }

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
        response
            .headers_mut()
            .insert("HX-Redirect", HeaderValue::from_static("/dashboard"));
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

/// Hash a token using SHA3-256 for secure storage.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Extract client IP from headers (X-Forwarded-For, X-Real-IP) or connection address.
fn extract_client_ip(headers: &HeaderMap, connect_addr: SocketAddr) -> IpNetwork {
    // Try X-Forwarded-For first (comma-separated list, first is original client)
    if let Some(xff) = headers.get("X-Forwarded-For") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first_ip) = xff_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<std::net::IpAddr>() {
                    return IpNetwork::from(ip);
                }
            }
        }
    }

    // Try X-Real-IP
    if let Some(real_ip) = headers.get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                return IpNetwork::from(ip);
            }
        }
    }

    // Fallback to the actual TCP connection address
    IpNetwork::from(connect_addr.ip())
}

/// Logout handler.
/// Invalidates the current session in the database and clears the cookie.
pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> Response {
    use axum::response::Redirect;
    use axum_extra::extract::cookie::Cookie;
    use time::Duration as TimeDuration;

    // Try to invalidate session in database and broadcast update
    if let Some(token_cookie) = jar.get("access_token") {
        let token_hash = hash_token(token_cookie.value());
        if let Ok(mut conn) = get_connection(&state.db_pool) {
            // First, get the user info from the session before deleting
            let user_info: Option<(i32, ::uuid::Uuid)> = auth_sessions::table
                .inner_join(crate::schema::users::table)
                .filter(auth_sessions::token_hash.eq(&token_hash))
                .select((crate::schema::users::id, crate::schema::users::uuid))
                .first(&mut conn)
                .ok();

            // Delete session by token hash
            let deleted = diesel::delete(
                auth_sessions::table.filter(auth_sessions::token_hash.eq(&token_hash)),
            )
            .execute(&mut conn)
            .unwrap_or(0);

            // Broadcast session update to other connected clients
            if deleted > 0 {
                if let Some((user_id, user_uuid_val)) = user_info {
                    crate::handlers::web::broadcast_sessions_update(
                        &state,
                        &user_uuid_val.to_string(),
                        user_id,
                    )
                    .await;
                }
            }
        }
    }

    let cookie = Cookie::build(("access_token", ""))
        .path("/")
        .http_only(true)
        .max_age(TimeDuration::ZERO)
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
    let user_uuid = UuidType::parse_str(&user.uuid)
        .map_err(|_| AppError::Validation("Invalid user UUID".to_string()))?;
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

    // ==================== extract_client_ip Tests ====================

    #[test]
    fn test_extract_client_ip_from_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "203.0.113.50, 70.41.3.18, 150.172.238.178".parse().unwrap());
        
        let fallback_addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let ip = extract_client_ip(&headers, fallback_addr);
        
        // Should return the first IP in X-Forwarded-For (the original client)
        assert_eq!(ip.ip().to_string(), "203.0.113.50");
    }

    #[test]
    fn test_extract_client_ip_from_x_forwarded_for_single() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "8.8.8.8".parse().unwrap());
        
        let fallback_addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let ip = extract_client_ip(&headers, fallback_addr);
        
        assert_eq!(ip.ip().to_string(), "8.8.8.8");
    }

    #[test]
    fn test_extract_client_ip_from_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "1.2.3.4".parse().unwrap());
        
        let fallback_addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let ip = extract_client_ip(&headers, fallback_addr);
        
        assert_eq!(ip.ip().to_string(), "1.2.3.4");
    }

    #[test]
    fn test_extract_client_ip_x_forwarded_for_takes_priority() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "203.0.113.50".parse().unwrap());
        headers.insert("X-Real-IP", "1.2.3.4".parse().unwrap());
        
        let fallback_addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let ip = extract_client_ip(&headers, fallback_addr);
        
        // X-Forwarded-For should take priority
        assert_eq!(ip.ip().to_string(), "203.0.113.50");
    }

    #[test]
    fn test_extract_client_ip_fallback_to_connect_addr() {
        let headers = HeaderMap::new(); // No proxy headers
        
        let fallback_addr: SocketAddr = "85.123.45.67:54321".parse().unwrap();
        let ip = extract_client_ip(&headers, fallback_addr);
        
        // Should use the TCP connection address
        assert_eq!(ip.ip().to_string(), "85.123.45.67");
    }

    #[test]
    fn test_extract_client_ip_ipv6() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "2001:db8::1".parse().unwrap());
        
        let fallback_addr: SocketAddr = "[::1]:12345".parse().unwrap();
        let ip = extract_client_ip(&headers, fallback_addr);
        
        assert_eq!(ip.ip().to_string(), "2001:db8::1");
    }

    #[test]
    fn test_extract_client_ip_fallback_ipv6() {
        let headers = HeaderMap::new();
        
        let fallback_addr: SocketAddr = "[2001:db8::abcd]:443".parse().unwrap();
        let ip = extract_client_ip(&headers, fallback_addr);
        
        assert_eq!(ip.ip().to_string(), "2001:db8::abcd");
    }

    #[test]
    fn test_extract_client_ip_invalid_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "not-an-ip-address".parse().unwrap());
        
        let fallback_addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let ip = extract_client_ip(&headers, fallback_addr);
        
        // Should fallback to connection address when header is invalid
        assert_eq!(ip.ip().to_string(), "10.0.0.1");
    }

    // ==================== hash_token Tests ====================

    #[test]
    fn test_hash_token_deterministic() {
        let token = "my-secret-jwt-token";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_token_different_inputs() {
        let hash1 = hash_token("token-a");
        let hash2 = hash_token("token-b");
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_token_length() {
        let hash = hash_token("any-token");
        
        // SHA3-256 produces a 64-character hex string
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hash_token_hex_format() {
        let hash = hash_token("test-token");
        
        // Should only contain hex characters
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
