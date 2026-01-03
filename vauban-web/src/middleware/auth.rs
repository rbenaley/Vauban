/// VAUBAN Web - Authentication middleware.
///
/// Extracts and validates JWT tokens from requests.

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
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
pub async fn auth_middleware(
    State(auth_service): State<AuthService>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Try to get token from Authorization header or cookie
    let token = extract_token(&jar, &request)?;

    if let Some(token) = token {
        match auth_service.verify_token(&token) {
            Ok(claims) => {
                let user = AuthUser {
                    uuid: claims.sub,
                    username: claims.username,
                    mfa_verified: claims.mfa_verified,
                    is_superuser: claims.is_superuser,
                    is_staff: claims.is_staff,
                };
                request.extensions_mut().insert(user);
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

/// Extract token from Authorization header or cookie.
fn extract_token(jar: &CookieJar, request: &Request) -> Result<Option<String>, AppError> {
    // Try Authorization header first
    if let Some(auth_header) = request.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                return Ok(Some(auth_str[7..].to_string()));
            }
        }
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
        return Err(AppError::Authorization("MFA verification required".to_string()));
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

