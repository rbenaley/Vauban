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
use axum_extra::extract::cookie::{Cookie, SameSite};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;
use crate::schema::{auth_sessions, users};

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
/// Requires both a valid session AND completed MFA verification.
/// Redirects to login if not authenticated, or to MFA page if MFA is pending.
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
        match parts.extensions.get::<AuthUser>().cloned() {
            Some(user) if user.mfa_verified => Ok(WebAuthUser(user)),
            Some(_) => Err(AppError::MfaRedirect),
            None => Err(AppError::AuthRedirect),
        }
    }
}

/// WebSocket authentication extractor.
///
/// Requires both a valid session AND completed MFA verification.
///
/// Unlike [`WebAuthUser`], this extractor does **not** redirect to
/// `/mfa/verify` because WebSocket clients cannot follow HTML redirects.
/// Pre-MFA tokens are rejected with `403 Forbidden`; missing tokens with
/// `401 Unauthorized`. The HTTP upgrade therefore fails cleanly and the
/// WebSocket is never opened.
///
/// This extractor is the third (innermost) layer of WebSocket MFA
/// enforcement. The other two layers are the [`super::super::handlers::websocket::ws_connection_limit`]
/// middleware (applied to every `/ws/*` route) and the
/// [`super::super::handlers::websocket::ws_session_guard`] middleware
/// (applied to session-bound routes). All three must reject pre-MFA
/// tokens so that a regression in any single layer does not unlock the
/// other two.
#[derive(Debug, Clone)]
pub struct WsAuthUser(pub AuthUser);

impl std::ops::Deref for WsAuthUser {
    type Target = AuthUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for WsAuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<AuthUser>().cloned() {
            Some(user) if user.mfa_verified => Ok(WsAuthUser(user)),
            Some(_) => Err(AppError::Authorization(
                "MFA verification required for WebSocket access".to_string(),
            )),
            None => Err(AppError::Auth(
                "Authentication required for WebSocket access".to_string(),
            )),
        }
    }
}

/// Pre-MFA web authentication extractor.
/// Requires a valid session but does NOT require MFA verification.
/// Use ONLY for MFA setup/verify pages and logout -- never for regular app pages.
#[derive(Debug, Clone)]
pub struct PreMfaAuthUser(pub AuthUser);

impl std::ops::Deref for PreMfaAuthUser {
    type Target = AuthUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for PreMfaAuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .map(PreMfaAuthUser)
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
/// Also updates last_activity on each authenticated request.
pub async fn auth_middleware(
    State(state): State<AppState>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token_info = extract_token_with_source(&jar, &request)?;

    if let Some((source, token)) = token_info {
        match state.auth_service.verify_token(&token) {
            Ok(claims) => {
                if let Some(session_uuid) =
                    verify_session_with_timeouts(&state, &token, &claims).await
                {
                    let user = AuthUser {
                        uuid: claims.sub.clone(),
                        username: claims.username.clone(),
                        mfa_verified: claims.mfa_verified,
                        is_superuser: claims.is_superuser,
                        is_staff: claims.is_staff,
                    };
                    request.extensions_mut().insert(user);

                    update_last_activity(&state, session_uuid).await;

                    let mut response = next.run(request).await;
                    maybe_rotate_access_cookie(
                        &state,
                        &claims,
                        session_uuid,
                        &source,
                        &mut response,
                    )
                    .await;
                    return Ok(response);
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

/// Verify that the session exists in the database and check timeout constraints.
/// Returns the `auth_sessions.uuid` if valid.
///
/// When the JWT carries `jti`, the row is keyed by `(jti, sub)` so rotated
/// access tokens (new `token_hash`) still match the same session. Legacy
/// tokens without `jti` fall back to lookup by `token_hash` of the presented
/// bearer.
///
/// Checks:
/// 1. Session exists and has not been revoked
/// 2. Session has not exceeded max_duration (created_at + session_max_duration_secs)
/// 3. Session has not exceeded idle timeout (last_activity + session_idle_timeout_secs)
async fn verify_session_with_timeouts(
    state: &AppState,
    token: &str,
    claims: &crate::services::auth::Claims,
) -> Option<Uuid> {
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    let Ok(mut conn) = state.db_pool.get().await else {
        tracing::warn!("Database unavailable for session verification; denying token");
        return None;
    };

    let now = chrono::Utc::now();
    let idle_timeout_secs = state.config.security.session_idle_timeout_secs as i64;
    let max_duration_secs = state.config.security.session_max_duration_secs as i64;

    let idle_cutoff = now - chrono::Duration::seconds(idle_timeout_secs);
    let max_duration_cutoff = now - chrono::Duration::seconds(max_duration_secs);

    if let Some(ref jti_str) = claims.jti
        && let (Ok(session_uuid), Ok(user_uuid)) =
            (Uuid::parse_str(jti_str), Uuid::parse_str(&claims.sub))
    {
        let count: i64 = auth_sessions::table
            .inner_join(users::table.on(users::id.eq(auth_sessions::user_id)))
            .filter(auth_sessions::uuid.eq(session_uuid))
            .filter(users::uuid.eq(user_uuid))
            .filter(auth_sessions::created_at.gt(max_duration_cutoff))
            .filter(auth_sessions::last_activity.gt(idle_cutoff))
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);
        if count > 0 {
            return Some(session_uuid);
        }
    }

    let user_uuid = Uuid::parse_str(&claims.sub).ok()?;
    auth_sessions::table
        .inner_join(users::table.on(users::id.eq(auth_sessions::user_id)))
        .filter(auth_sessions::token_hash.eq(&token_hash))
        .filter(users::uuid.eq(user_uuid))
        .filter(auth_sessions::created_at.gt(max_duration_cutoff))
        .filter(auth_sessions::last_activity.gt(idle_cutoff))
        .select(auth_sessions::uuid)
        .first::<Uuid>(&mut conn)
        .await
        .optional()
        .ok()
        .flatten()
}

/// Update the last_activity timestamp for the session.
/// This is called on each authenticated request to track user activity.
async fn update_last_activity(state: &AppState, session_uuid: Uuid) {
    if let Ok(mut conn) = state.db_pool.get().await {
        let _ = diesel::update(
            auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)),
        )
        .set(auth_sessions::last_activity.eq(chrono::Utc::now()))
        .execute(&mut conn)
        .await;
    }
}

/// Where the bearer access token was read from (Bearer wins over cookie).
#[derive(Debug, Clone)]
enum TokenSource {
    Bearer,
    Cookie,
}

/// Extract `(source, token)` from Authorization header or cookie.
///
/// Per RFC 7235 s2.1 and RFC 6750 s2.1, the "Bearer" authentication scheme
/// must be compared case-insensitively.
fn extract_token_with_source(
    jar: &CookieJar,
    request: &Request,
) -> Result<Option<(TokenSource, String)>, AppError> {
    if let Some(auth_header) = request.headers().get("Authorization")
        && let Ok(auth_str) = auth_header.to_str()
        && auth_str.len() >= 7
        && auth_str[..7].eq_ignore_ascii_case("bearer ")
    {
        return Ok(Some((TokenSource::Bearer, auth_str[7..].to_string())));
    }

    if let Some(token_cookie) = jar.get("access_token") {
        return Ok(Some((
            TokenSource::Cookie,
            token_cookie.value().to_string(),
        )));
    }

    Ok(None)
}

async fn maybe_rotate_access_cookie(
    state: &AppState,
    claims: &crate::services::auth::Claims,
    session_uuid: Uuid,
    source: &TokenSource,
    response: &mut Response,
) {
    if !matches!(source, TokenSource::Cookie) {
        return;
    }

    let now = chrono::Utc::now().timestamp();
    let renew_within = state.auth_service.access_token_renew_if_expires_within_seconds();
    if claims.exp - now > renew_within {
        return;
    }

    let Ok(new_token) = state.auth_service.generate_access_token(
        &claims.sub,
        &claims.username,
        claims.mfa_verified,
        claims.is_superuser,
        claims.is_staff,
        Some(session_uuid),
    ) else {
        return;
    };

    let mut hasher = Sha3_256::new();
    hasher.update(new_token.as_bytes());
    let new_hash = format!("{:x}", hasher.finalize());
    let now_ts = chrono::Utc::now();

    let Ok(mut conn) = state.db_pool.get().await else {
        return;
    };

    let updated = diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set((
            auth_sessions::token_hash.eq(new_hash),
            auth_sessions::last_activity.eq(now_ts),
        ))
        .execute(&mut conn)
        .await
        .unwrap_or(0);

    if updated == 0 {
        return;
    }

    let cookie = Cookie::build(("access_token", new_token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();

    if let Ok(header_value) = cookie.to_string().parse() {
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, header_value);
    }
}

/// Require authentication.
/// Validates the JWT token AND verifies the session exists in the database
/// (to support session revocation). Also updates last_activity.
pub async fn require_auth(
    State(state): State<AppState>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let (source, token) = extract_token_with_source(&jar, &request)?
        .ok_or_else(|| AppError::Auth("Authentication required".to_string()))?;

    let claims = state.auth_service.verify_token(&token)?;

    let session_uuid = verify_session_with_timeouts(&state, &token, &claims)
        .await
        .ok_or_else(|| AppError::Auth("Session revoked or expired".to_string()))?;

    let user = AuthUser {
        uuid: claims.sub.clone(),
        username: claims.username.clone(),
        mfa_verified: claims.mfa_verified,
        is_superuser: claims.is_superuser,
        is_staff: claims.is_staff,
    };

    let mut request = request;
    request.extensions_mut().insert(user);

    update_last_activity(&state, session_uuid).await;

    let mut response = next.run(request).await;
    maybe_rotate_access_cookie(
        &state,
        &claims,
        session_uuid,
        &source,
        &mut response,
    )
    .await;

    Ok(response)
}

/// Require MFA verification.
/// Validates the JWT token, verifies MFA status, AND verifies the session
/// exists in the database (to support session revocation). Also updates last_activity.
pub async fn require_mfa(
    State(state): State<AppState>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let (source, token) = extract_token_with_source(&jar, &request)?
        .ok_or_else(|| AppError::Auth("Authentication required".to_string()))?;

    let claims = state.auth_service.verify_token(&token)?;

    if !claims.mfa_verified {
        return Err(AppError::Authorization(
            "MFA verification required".to_string(),
        ));
    }

    let session_uuid = verify_session_with_timeouts(&state, &token, &claims)
        .await
        .ok_or_else(|| AppError::Auth("Session revoked or expired".to_string()))?;

    let user = AuthUser {
        uuid: claims.sub.clone(),
        username: claims.username.clone(),
        mfa_verified: true,
        is_superuser: claims.is_superuser,
        is_staff: claims.is_staff,
    };

    let mut request = request;
    request.extensions_mut().insert(user);

    update_last_activity(&state, session_uuid).await;

    let mut response = next.run(request).await;
    maybe_rotate_access_cookie(
        &state,
        &claims,
        session_uuid,
        &source,
        &mut response,
    )
    .await;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::response::IntoResponse;

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
        let request = unwrap_ok!(
            HttpRequest::builder()
                .header("Authorization", "Bearer my-jwt-token-123")
                .body(axum::body::Body::empty())
        );

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token_with_source(&jar, &request).map(|o| o.map(|(_, t)| t)));

        assert_eq!(result, Some("my-jwt-token-123".to_string()));
    }

    #[test]
    fn test_extract_token_bearer_case_insensitive() {
        // RFC 7235 requires case-insensitive scheme comparison
        for prefix in &["Bearer ", "bearer ", "BEARER ", "bEaReR "] {
            let request = unwrap_ok!(
                HttpRequest::builder()
                    .header("Authorization", format!("{}my-token", prefix))
                    .body(axum::body::Body::empty())
            );

            let jar = CookieJar::new();
            let result = unwrap_ok!(extract_token_with_source(&jar, &request).map(|o| o.map(|(_, t)| t)));

            assert_eq!(
                result,
                Some("my-token".to_string()),
                "Bearer prefix '{}' should be accepted (RFC 7235)",
                prefix.trim()
            );
        }
    }

    #[test]
    fn test_extract_token_no_auth_returns_none() {
        let request = unwrap_ok!(HttpRequest::builder().body(axum::body::Body::empty()));

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token_with_source(&jar, &request).map(|o| o.map(|(_, t)| t)));

        assert!(result.is_none());
    }

    #[test]
    fn test_extract_token_invalid_auth_scheme() {
        let request = unwrap_ok!(
            HttpRequest::builder()
                .header("Authorization", "Basic dXNlcjpwYXNz")
                .body(axum::body::Body::empty())
        );

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token_with_source(&jar, &request).map(|o| o.map(|(_, t)| t)));

        // Basic auth should not be extracted
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_token_empty_bearer() {
        let request = unwrap_ok!(
            HttpRequest::builder()
                .header("Authorization", "Bearer ")
                .body(axum::body::Body::empty())
        );

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token_with_source(&jar, &request).map(|o| o.map(|(_, t)| t)));

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
        let request = unwrap_ok!(
            HttpRequest::builder()
                .header("Authorization", format!("Bearer {}", long_token))
                .body(axum::body::Body::empty())
        );

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token_with_source(&jar, &request).map(|o| o.map(|(_, t)| t)));

        assert_eq!(result, Some(long_token));
    }

    #[test]
    fn test_extract_token_bearer_with_special_chars() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123-_";
        let request = unwrap_ok!(
            HttpRequest::builder()
                .header("Authorization", format!("Bearer {}", token))
                .body(axum::body::Body::empty())
        );

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token_with_source(&jar, &request).map(|o| o.map(|(_, t)| t)));

        assert_eq!(result, Some(token.to_string()));
    }

    #[test]
    fn test_extract_token_no_auth_header() {
        let request = unwrap_ok!(
            HttpRequest::builder()
                .header("Content-Type", "application/json")
                .body(axum::body::Body::empty())
        );

        let jar = CookieJar::new();
        let result = unwrap_ok!(extract_token_with_source(&jar, &request).map(|o| o.map(|(_, t)| t)));

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

    // ==================== WebAuthUser MFA Enforcement Tests ====================

    #[tokio::test]
    async fn test_web_auth_user_rejects_pre_mfa_session() {
        let pre_mfa_user = AuthUser {
            uuid: "uuid".to_string(),
            username: "user".to_string(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
        };

        let mut parts = unwrap_ok!(HttpRequest::builder().body(axum::body::Body::empty()))
            .into_parts()
            .0;
        parts.extensions.insert(pre_mfa_user);

        let result = WebAuthUser::from_request_parts(&mut parts, &()).await;
        assert!(
            result.is_err(),
            "WebAuthUser must reject mfa_verified=false"
        );
        let err_response = result.unwrap_err().into_response();
        assert_eq!(err_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            unwrap_ok!(unwrap_some!(err_response.headers().get("location")).to_str()),
            "/mfa/verify"
        );
    }

    #[tokio::test]
    async fn test_web_auth_user_accepts_mfa_verified_session() {
        let mfa_user = AuthUser {
            uuid: "uuid".to_string(),
            username: "user".to_string(),
            mfa_verified: true,
            is_superuser: false,
            is_staff: false,
        };

        let mut parts = unwrap_ok!(HttpRequest::builder().body(axum::body::Body::empty()))
            .into_parts()
            .0;
        parts.extensions.insert(mfa_user);

        let result = WebAuthUser::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok(), "WebAuthUser must accept mfa_verified=true");
    }

    #[tokio::test]
    async fn test_web_auth_user_redirects_to_login_when_no_session() {
        let mut parts = unwrap_ok!(HttpRequest::builder().body(axum::body::Body::empty()))
            .into_parts()
            .0;

        let result = WebAuthUser::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err());
        let err_response = result.unwrap_err().into_response();
        assert_eq!(err_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            unwrap_ok!(unwrap_some!(err_response.headers().get("location")).to_str()),
            "/login"
        );
    }

    // ==================== PreMfaAuthUser Tests ====================

    #[test]
    fn test_pre_mfa_auth_user_deref() {
        let auth_user = create_test_user();
        let pre_mfa = PreMfaAuthUser(auth_user.clone());
        assert_eq!(pre_mfa.uuid, auth_user.uuid);
        assert_eq!(pre_mfa.username, auth_user.username);
    }

    #[test]
    fn test_pre_mfa_auth_user_clone() {
        let auth_user = create_test_user();
        let pre_mfa = PreMfaAuthUser(auth_user);
        let cloned = pre_mfa.clone();
        assert_eq!(pre_mfa.uuid, cloned.uuid);
    }

    #[test]
    fn test_pre_mfa_auth_user_debug() {
        let auth_user = create_test_user();
        let pre_mfa = PreMfaAuthUser(auth_user);
        let debug_str = format!("{:?}", pre_mfa);
        assert!(debug_str.contains("PreMfaAuthUser"));
    }

    #[tokio::test]
    async fn test_pre_mfa_auth_user_accepts_unverified_mfa() {
        let pre_mfa_user = AuthUser {
            uuid: "uuid".to_string(),
            username: "user".to_string(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
        };

        let mut parts = unwrap_ok!(HttpRequest::builder().body(axum::body::Body::empty()))
            .into_parts()
            .0;
        parts.extensions.insert(pre_mfa_user);

        let result = PreMfaAuthUser::from_request_parts(&mut parts, &()).await;
        assert!(
            result.is_ok(),
            "PreMfaAuthUser must accept mfa_verified=false"
        );
    }

    #[tokio::test]
    async fn test_pre_mfa_auth_user_accepts_verified_mfa() {
        let mfa_user = AuthUser {
            uuid: "uuid".to_string(),
            username: "user".to_string(),
            mfa_verified: true,
            is_superuser: false,
            is_staff: false,
        };

        let mut parts = unwrap_ok!(HttpRequest::builder().body(axum::body::Body::empty()))
            .into_parts()
            .0;
        parts.extensions.insert(mfa_user);

        let result = PreMfaAuthUser::from_request_parts(&mut parts, &()).await;
        assert!(
            result.is_ok(),
            "PreMfaAuthUser must also accept mfa_verified=true"
        );
    }

    #[tokio::test]
    async fn test_pre_mfa_auth_user_redirects_to_login_when_no_session() {
        let mut parts = unwrap_ok!(HttpRequest::builder().body(axum::body::Body::empty()))
            .into_parts()
            .0;

        let result = PreMfaAuthUser::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err());
        let err_response = result.unwrap_err().into_response();
        assert_eq!(
            unwrap_ok!(unwrap_some!(err_response.headers().get("location")).to_str()),
            "/login"
        );
    }

    // ==================== WsAuthUser MFA Enforcement Tests ====================
    //
    // These tests guard the third (innermost) layer of the WebSocket MFA
    // defence. A regression here would let a pre-MFA token open any
    // WebSocket whose handler accepts `WsAuthUser`. See `ws_session_guard`
    // and `ws_connection_limit` for the other two layers.

    #[test]
    fn test_ws_auth_user_deref() {
        let auth_user = create_test_user();
        let ws_user = WsAuthUser(auth_user.clone());
        assert_eq!(ws_user.uuid, auth_user.uuid);
        assert_eq!(ws_user.username, auth_user.username);
    }

    #[test]
    fn test_ws_auth_user_clone() {
        let auth_user = create_test_user();
        let ws_user = WsAuthUser(auth_user);
        let cloned = ws_user.clone();
        assert_eq!(ws_user.uuid, cloned.uuid);
    }

    #[tokio::test]
    async fn test_ws_auth_user_accepts_mfa_verified_session() {
        let mfa_user = AuthUser {
            uuid: "uuid".to_string(),
            username: "user".to_string(),
            mfa_verified: true,
            is_superuser: false,
            is_staff: false,
        };

        let mut parts = unwrap_ok!(HttpRequest::builder().body(axum::body::Body::empty()))
            .into_parts()
            .0;
        parts.extensions.insert(mfa_user);

        let result = WsAuthUser::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok(), "WsAuthUser must accept mfa_verified=true");
    }

    /// Critical regression test: a pre-MFA token must NEVER unlock a
    /// WebSocket. The historical bug let `mfa_verified=false` tokens
    /// reach `/ws/dashboard`, `/ws/notifications`, etc.
    #[tokio::test]
    async fn test_ws_auth_user_rejects_pre_mfa_with_403_no_redirect() {
        let pre_mfa_user = AuthUser {
            uuid: "uuid".to_string(),
            username: "user".to_string(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
        };

        let mut parts = unwrap_ok!(HttpRequest::builder().body(axum::body::Body::empty()))
            .into_parts()
            .0;
        parts.extensions.insert(pre_mfa_user);

        let result = WsAuthUser::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err(), "WsAuthUser must reject pre-MFA tokens");
        let err_response = result.unwrap_err().into_response();
        assert_eq!(
            err_response.status(),
            StatusCode::FORBIDDEN,
            "Pre-MFA WS rejection must be 403 (not a 303 redirect): WS clients \
             cannot follow HTML redirects so a redirect would mask the rejection"
        );
        assert!(
            err_response.headers().get("location").is_none(),
            "WsAuthUser must NEVER emit a Location header (no redirect for WS)"
        );
    }

    #[tokio::test]
    async fn test_ws_auth_user_rejects_no_session_with_401() {
        let mut parts = unwrap_ok!(HttpRequest::builder().body(axum::body::Body::empty()))
            .into_parts()
            .0;

        let result = WsAuthUser::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err());
        let err_response = result.unwrap_err().into_response();
        assert_eq!(err_response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            err_response.headers().get("location").is_none(),
            "WsAuthUser must NEVER emit a Location header (no redirect for WS)"
        );
    }
}
