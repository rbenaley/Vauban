/// VAUBAN Web - Authentication middleware.
///
/// Extracts and validates JWT tokens from requests.
/// Sessions are validated against the database to support revocation.
use axum::{
    extract::{FromRequestParts, Request, State},
    http::request::Parts,
    middleware::Next,
    response::Response,
};
use axum_extra::extract::CookieJar;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::AppState;
use crate::db::get_connection;
use crate::error::AppError;
use crate::schema::auth_sessions;
use crate::services::auth::AuthService;

/// Authenticated user context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub uuid: String,
    pub username: String,
    pub mfa_verified: bool,
    pub is_superuser: bool,
    pub is_staff: bool,
}

/// Implement FromRequestParts for AuthUser to extract from request extensions.
/// Used by API endpoints - returns JSON 401 error if not authenticated.
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .ok_or_else(|| AppError::Auth("Authentication required".to_string()))
    }
}

/// Web page authentication extractor.
/// Same as AuthUser but redirects to login page instead of returning JSON 401.
/// Use this for web page handlers (HTML responses).
#[derive(Debug, Clone)]
pub struct WebAuthUser(pub AuthUser);

impl std::ops::Deref for WebAuthUser {
    type Target = AuthUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for WebAuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .map(WebAuthUser)
            .ok_or(AppError::AuthRedirect)
    }
}

/// Optional AuthUser extractor for pages that don't require authentication.
pub struct OptionalAuthUser(pub Option<AuthUser>);

impl<S> FromRequestParts<S> for OptionalAuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user = parts.extensions.get::<AuthUser>().cloned();
        Ok(OptionalAuthUser(user))
    }
}

/// Extract authenticated user from request.
/// Validates JWT token and verifies session exists in database (for revocation support).
pub async fn auth_middleware(
    State(state): State<AppState>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Try to get token from Authorization header or cookie
    let token = extract_token(&jar, &request)?;

    if let Some(token) = token {
        match state.auth_service.verify_token(&token) {
            Ok(claims) => {
                // Verify session exists in database (supports revocation)
                if verify_session_exists(&state, &token) {
                    let user = AuthUser {
                        uuid: claims.sub,
                        username: claims.username,
                        mfa_verified: claims.mfa_verified,
                        is_superuser: claims.is_superuser,
                        is_staff: claims.is_staff,
                    };
                    request.extensions_mut().insert(user);
                } else {
                    tracing::debug!("Session not found in database (revoked or expired)");
                }
            }
            Err(e) => {
                // Log the error but don't fail - just continue without authentication
                // This allows pages using OptionalAuthUser to work with expired tokens
                tracing::debug!("Token verification failed (ignoring): {}", e);
            }
        }
    }

    Ok(next.run(request).await)
}

/// Verify that the session exists in the database.
/// Returns false if the session has been revoked or doesn't exist.
fn verify_session_exists(state: &AppState, token: &str) -> bool {
    // Hash the token
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    // Check database
    if let Ok(mut conn) = get_connection(&state.db_pool) {
        let exists: Result<i64, _> = auth_sessions::table
            .filter(auth_sessions::token_hash.eq(&token_hash))
            .filter(auth_sessions::expires_at.gt(chrono::Utc::now()))
            .count()
            .get_result(&mut conn);

        matches!(exists, Ok(count) if count > 0)
    } else {
        // Fail closed: if session verification cannot be performed, deny auth.
        tracing::warn!("Database unavailable for session verification; denying token");
        false
    }
}

/// Extract token from Authorization header or cookie.
fn extract_token(jar: &CookieJar, request: &Request) -> Result<Option<String>, AppError> {
    // Try Authorization header first
    if let Some(auth_header) = request.headers().get("Authorization")
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        return Ok(Some(token.to_string()));
    }

    // Try cookie
    if let Some(token_cookie) = jar.get("access_token") {
        return Ok(Some(token_cookie.value().to_string()));
    }

    Ok(None)
}

/// Require authentication.
pub async fn require_auth(
    State(auth_service): State<AuthService>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_token(&jar, &request)?
        .ok_or_else(|| AppError::Auth("Authentication required".to_string()))?;

    let claims = auth_service.verify_token(&token)?;
    let user = AuthUser {
        uuid: claims.sub,
        username: claims.username,
        mfa_verified: claims.mfa_verified,
        is_superuser: claims.is_superuser,
        is_staff: claims.is_staff,
    };

    let mut request = request;
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}

/// Require MFA verification.
pub async fn require_mfa(
    State(auth_service): State<AuthService>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_token(&jar, &request)?
        .ok_or_else(|| AppError::Auth("Authentication required".to_string()))?;

    let claims = auth_service.verify_token(&token)?;

    if !claims.mfa_verified {
        return Err(AppError::Authorization(
            "MFA verification required".to_string(),
        ));
    }

    let user = AuthUser {
        uuid: claims.sub,
        username: claims.username,
        mfa_verified: true,
        is_superuser: claims.is_superuser,
        is_staff: claims.is_staff,
    };

    let mut request = request;
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    

    // ==================== AuthUser Tests ====================

    fn create_test_user() -> AuthUser {
        AuthUser {
            uuid: "test-uuid-123".to_string(),
            username: "testuser".to_string(),
            mfa_verified: true,
            is_superuser: false,
            is_staff: true,
        }
    }

    #[test]
    fn test_auth_user_clone() {
        let user = create_test_user();
        let cloned = user.clone();

        assert_eq!(user.uuid, cloned.uuid);
        assert_eq!(user.username, cloned.username);
        assert_eq!(user.mfa_verified, cloned.mfa_verified);
        assert_eq!(user.is_superuser, cloned.is_superuser);
        assert_eq!(user.is_staff, cloned.is_staff);
    }

    #[test]
    fn test_auth_user_debug() {
        let user = create_test_user();
        let debug_str = format!("{:?}", user);

        assert!(debug_str.contains("AuthUser"));
        assert!(debug_str.contains("testuser"));
    }

    #[test]
    fn test_auth_user_serialize() {
        let user = create_test_user();
        let json = unwrap_ok!(serde_json::to_string(&user));

        assert!(json.contains("test-uuid-123"));
        assert!(json.contains("testuser"));
        assert!(json.contains("mfa_verified"));
    }

    #[test]
    fn test_auth_user_deserialize() {
        let json = r#"{
            "uuid": "abc-123",
            "username": "admin",
            "mfa_verified": false,
            "is_superuser": true,
            "is_staff": true
        }"#;

        let user: AuthUser = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(user.uuid, "abc-123");
        assert_eq!(user.username, "admin");
        assert!(!user.mfa_verified);
        assert!(user.is_superuser);
        assert!(user.is_staff);
    }

    // ==================== OptionalAuthUser Tests ====================

    #[test]
    fn test_optional_auth_user_none() {
        let opt = OptionalAuthUser(None);
        assert!(opt.0.is_none());
    }

    #[test]
    fn test_optional_auth_user_some() {
        let user = create_test_user();
        let opt = OptionalAuthUser(Some(user));

        assert!(opt.0.is_some());
        assert_eq!(unwrap_some!(opt.0).username, "testuser");
    }

    // ==================== extract_token Tests ====================

    #[test]
    fn test_extract_token_from_bearer_header() {
        let request = unwrap_ok!(HttpRequest::builder()
            .header("Authorization", "Bearer my-jwt-token-123")
            .body(axum::body::Body::empty()));

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token(&jar, &request));

        assert_eq!(result, Some("my-jwt-token-123".to_string()));
    }

    #[test]
    fn test_extract_token_bearer_case_sensitive() {
        // "bearer" lowercase should not match
        let request = unwrap_ok!(HttpRequest::builder()
            .header("Authorization", "bearer lowercase-token")
            .body(axum::body::Body::empty()));

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token(&jar, &request));

        // Should not extract because it's "bearer" not "Bearer"
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_token_no_auth_returns_none() {
        let request = unwrap_ok!(HttpRequest::builder()
            .body(axum::body::Body::empty()));

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token(&jar, &request));

        assert!(result.is_none());
    }

    #[test]
    fn test_extract_token_invalid_auth_scheme() {
        let request = unwrap_ok!(HttpRequest::builder()
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(axum::body::Body::empty()));

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token(&jar, &request));

        // Basic auth should not be extracted
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_token_empty_bearer() {
        let request = unwrap_ok!(HttpRequest::builder()
            .header("Authorization", "Bearer ")
            .body(axum::body::Body::empty()));

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token(&jar, &request));

        // Should return empty string (the code after "Bearer ")
        assert_eq!(result, Some("".to_string()));
    }

    // ==================== Additional AuthUser Tests ====================

    #[test]
    fn test_auth_user_superuser_flag() {
        let user = AuthUser {
            uuid: "admin-uuid".to_string(),
            username: "admin".to_string(),
            mfa_verified: true,
            is_superuser: true,
            is_staff: true,
        };

        assert!(user.is_superuser);
        assert!(user.is_staff);
    }

    #[test]
    fn test_auth_user_regular_user() {
        let user = AuthUser {
            uuid: "regular-uuid".to_string(),
            username: "regular".to_string(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
        };

        assert!(!user.is_superuser);
        assert!(!user.is_staff);
        assert!(!user.mfa_verified);
    }

    #[test]
    fn test_auth_user_empty_fields() {
        let user = AuthUser {
            uuid: "".to_string(),
            username: "".to_string(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
        };

        assert_eq!(user.uuid, "");
        assert_eq!(user.username, "");
    }

    #[test]
    fn test_auth_user_unicode_username() {
        let user = AuthUser {
            uuid: "uuid".to_string(),
            username: "用户名".to_string(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
        };

        assert_eq!(user.username, "用户名");
    }

    // ==================== OptionalAuthUser Additional Tests ====================

    #[test]
    fn test_optional_auth_user_unwrap_or_default() {
        let opt = OptionalAuthUser(None);
        let user = opt.0.unwrap_or(AuthUser {
            uuid: "default".to_string(),
            username: "anonymous".to_string(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
        });

        assert_eq!(user.username, "anonymous");
    }

    #[test]
    fn test_optional_auth_user_is_some() {
        let user = create_test_user();
        let opt = OptionalAuthUser(Some(user));

        assert!(opt.0.is_some());
    }

    #[test]
    fn test_optional_auth_user_is_none() {
        let opt = OptionalAuthUser(None);

        assert!(opt.0.is_none());
    }

    // ==================== extract_token Additional Tests ====================

    #[test]
    fn test_extract_token_bearer_with_long_token() {
        let long_token = "a".repeat(1000);
        let request = unwrap_ok!(HttpRequest::builder()
            .header("Authorization", format!("Bearer {}", long_token))
            .body(axum::body::Body::empty()));

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token(&jar, &request));

        assert_eq!(result, Some(long_token));
    }

    #[test]
    fn test_extract_token_bearer_with_special_chars() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123-_";
        let request = unwrap_ok!(HttpRequest::builder()
            .header("Authorization", format!("Bearer {}", token))
            .body(axum::body::Body::empty()));

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token(&jar, &request));

        assert_eq!(result, Some(token.to_string()));
    }

    #[test]
    fn test_extract_token_no_auth_header() {
        let request = unwrap_ok!(HttpRequest::builder()
            .header("Content-Type", "application/json")
            .body(axum::body::Body::empty()));

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token(&jar, &request));

        assert!(result.is_none());
    }

    // ==================== AuthUser Serialization Tests ====================

    #[test]
    fn test_auth_user_json_roundtrip() {
        let user = create_test_user();
        let json = unwrap_ok!(serde_json::to_string(&user));
        let deserialized: AuthUser = unwrap_ok!(serde_json::from_str(&json));

        assert_eq!(user.uuid, deserialized.uuid);
        assert_eq!(user.username, deserialized.username);
        assert_eq!(user.mfa_verified, deserialized.mfa_verified);
    }

    #[test]
    fn test_auth_user_all_false_flags() {
        let user = AuthUser {
            uuid: "uuid".to_string(),
            username: "basic".to_string(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
        };

        assert!(!user.mfa_verified);
        assert!(!user.is_superuser);
        assert!(!user.is_staff);
    }

    #[test]
    fn test_auth_user_all_true_flags() {
        let user = AuthUser {
            uuid: "uuid".to_string(),
            username: "superadmin".to_string(),
            mfa_verified: true,
            is_superuser: true,
            is_staff: true,
        };

        assert!(user.mfa_verified);
        assert!(user.is_superuser);
        assert!(user.is_staff);
    }

    // ==================== WebAuthUser Tests ====================

    #[test]
    fn test_web_auth_user_deref() {
        let auth_user = create_test_user();
        let web_user = WebAuthUser(auth_user.clone());

        // WebAuthUser derefs to AuthUser
        assert_eq!(web_user.uuid, auth_user.uuid);
        assert_eq!(web_user.username, auth_user.username);
        assert_eq!(web_user.is_superuser, auth_user.is_superuser);
    }

    #[test]
    fn test_web_auth_user_clone() {
        let auth_user = create_test_user();
        let web_user = WebAuthUser(auth_user);
        let cloned = web_user.clone();

        assert_eq!(web_user.uuid, cloned.uuid);
        assert_eq!(web_user.username, cloned.username);
    }

    #[test]
    fn test_web_auth_user_debug() {
        let auth_user = create_test_user();
        let web_user = WebAuthUser(auth_user);
        let debug_str = format!("{:?}", web_user);

        assert!(debug_str.contains("WebAuthUser"));
        assert!(debug_str.contains("testuser"));
    }

    #[test]
    fn test_web_auth_user_inner_access() {
        let auth_user = AuthUser {
            uuid: "web-uuid".to_string(),
            username: "webuser".to_string(),
            mfa_verified: true,
            is_superuser: false,
            is_staff: true,
        };
        let web_user = WebAuthUser(auth_user);

        // Access inner AuthUser via .0
        assert_eq!(web_user.0.uuid, "web-uuid");
        assert_eq!(web_user.0.username, "webuser");
        assert!(web_user.0.mfa_verified);
        assert!(!web_user.0.is_superuser);
        assert!(web_user.0.is_staff);
    }
}
