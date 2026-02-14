/// VAUBAN Web - Authentication handlers.
///
/// Login, logout, MFA setup and verification.
use axum::{
    Json,
    extract::{Form, State},
    http::{HeaderValue, StatusCode, header::HeaderMap},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use ipnetwork::IpNetwork;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::net::SocketAddr;
use validator::Validate;
use zeroize::Zeroize;

use askama::Template;

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::flash::{IncomingFlash, flash_redirect};
use crate::models::auth_session::{AuthSession, NewAuthSession};
use crate::models::user::User;
use crate::schema::{auth_sessions, users::dsl::*};
use crate::services::auth::AuthService;
use crate::templates::accounts::{MfaSetupTemplate, MfaVerifyTemplate};
use crate::templates::base::BaseTemplate;

/// Check whether a value looks like an encrypted ciphertext from vauban-vault.
///
/// Encrypted values have the format `"v{digit(s)}:{base64}"`.
/// This is used for backward compatibility: plaintext secrets (pre-migration)
/// are verified directly via `AuthService::verify_totp`, while encrypted
/// secrets are sent to the vault for decryption + verification.
fn is_encrypted(value: &str) -> bool {
    if value.len() < 4 {
        return false;
    }
    if !value.starts_with('v') {
        return false;
    }
    let Some(colon_pos) = value.find(':') else {
        return false;
    };
    if colon_pos < 2 {
        return false;
    }
    value[1..colon_pos].chars().all(|c| c.is_ascii_digit())
}

// L-6: is_htmx_request deduplicated - use crate::error::is_htmx_request
use crate::error::is_htmx_request;

/// Login request.
///
/// `Debug` is manually implemented to redact the `password` and `mfa_code`
/// fields, preventing accidental credential leaks in logs (H-4).
#[derive(Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 3))]
    pub username: String,
    #[validate(length(min = 12))]
    pub password: String,
    pub mfa_code: Option<String>,
    pub csrf_token: Option<String>,
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("mfa_code", &self.mfa_code.as_ref().map(|_| "[REDACTED]"))
            .field("csrf_token", &self.csrf_token)
            .finish()
    }
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
    client_addr: crate::middleware::ClientAddr,
    headers: HeaderMap,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> AppResult<Response> {
    let client_addr = client_addr.addr();
    let htmx = is_htmx_request(&headers);

    // Rate limiting check
    let rate_key = client_addr.ip().to_string();
    let rate_result = state.rate_limiter.check(&rate_key).await?;
    if !rate_result.allowed {
        if htmx {
            return Ok(Html(login_error_html(LoginErrorKind::RateLimited)).into_response());
        }
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("Retry-After", rate_result.reset_in_secs.to_string()),
                ("X-RateLimit-Remaining", "0".to_string()),
            ],
            Json(serde_json::json!({
                "error": "Too many login attempts. Please try again later.",
                "retry_after": rate_result.reset_in_secs
            })),
        )
            .into_response());
    }

    // Validation
    if let Err(e) = validator::Validate::validate(&request) {
        if htmx {
            return Ok(Html(login_error_html(LoginErrorKind::ValidationError)).into_response());
        }
        return Err(AppError::Validation(format!("Validation failed: {:?}", e)));
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Database connection error: {}", e)))?;

    // Find user by username
    let user = match users
        .filter(username.eq(&request.username))
        .filter(is_deleted.eq(false))
        .first::<User>(&mut conn)
        .await
        .optional()
        .map_err(AppError::Database)?
    {
        Some(u) => u,
        None => {
            if htmx {
                return Ok(
                    Html(login_error_html(LoginErrorKind::InvalidCredentials)).into_response()
                );
            }
            return Err(AppError::Auth("Invalid credentials".to_string()));
        }
    };

    // Check if account is locked
    if user.is_locked() {
        if htmx {
            return Ok(Html(login_error_html(LoginErrorKind::AccountLocked)).into_response());
        }
        return Err(AppError::Auth("Account is locked".to_string()));
    }

    // Verify password
    let password_valid = state
        .auth_service
        .verify_password(&request.password, &user.password_hash)?;
    if !password_valid {
        // Increment failed attempts and apply progressive lockout if needed
        let max_failed_attempts = state.config.security.max_failed_login_attempts as i32;
        let new_failed_attempts = user.failed_login_attempts + 1;
        let locked_until_value = lockout_duration_for_attempts(
            new_failed_attempts,
            state.config.security.max_failed_login_attempts,
        )
        .map(|duration| Utc::now() + duration);

        diesel::update(users.find(user.id))
            .set((
                failed_login_attempts.eq(new_failed_attempts),
                locked_until.eq(locked_until_value),
            ))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;

        if locked_until_value.is_some() && new_failed_attempts >= max_failed_attempts {
            if htmx {
                return Ok(Html(login_error_html(LoginErrorKind::AccountLocked)).into_response());
            }
            return Err(AppError::Auth("Account is locked".to_string()));
        }

        if htmx {
            return Ok(Html(login_error_html(LoginErrorKind::InvalidCredentials)).into_response());
        }
        return Err(AppError::Auth("Invalid credentials".to_string()));
    }

    // MFA handling - for web (HTMX), redirect to MFA pages
    // For API (JSON), handle inline or return mfa_required
    if htmx {
        // Web flow: always generate temporary token and redirect to MFA page
        // Reset failed attempts first
        diesel::update(users.find(user.id))
            .set((
                failed_login_attempts.eq(0),
                locked_until.eq(None::<chrono::DateTime<chrono::Utc>>),
                last_login.eq(chrono::Utc::now()),
            ))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;

        // Generate temporary token with mfa_verified = false
        let temp_token = state.auth_service.generate_access_token(
            &user.uuid.to_string(),
            &user.username,
            false, // mfa_verified = false
            user.is_superuser,
            user.is_staff,
        )?;

        // Create auth session with temporary token
        let token_hash = hash_token(&temp_token);
        let trusted = state.config.security.parsed_trusted_proxies();
        let client_ip = extract_client_ip(&headers, client_addr, &trusted);
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
        .await
        .ok();

        // Insert new session
        // expires_at is set to session_max_duration_secs from config (absolute max lifetime)
        let new_session = NewAuthSession {
            uuid: ::uuid::Uuid::new_v4(),
            user_id: user.id,
            token_hash,
            ip_address: client_ip,
            user_agent: user_agent_str,
            device_info,
            expires_at: Utc::now()
                + Duration::seconds(state.config.security.session_max_duration_secs as i64),
            is_current: true,
        };

        diesel::insert_into(auth_sessions::table)
            .values(&new_session)
            .execute(&mut conn)
            .await
            .ok();

        // Set cookie with temporary token
        use axum_extra::extract::cookie::{Cookie, SameSite};
        let cookie = Cookie::build(("access_token", temp_token))
            .path("/")
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .build();

        // Redirect based on MFA state
        let redirect_url = if user.mfa_enabled {
            "/mfa/verify" // MFA enabled: verify code
        } else {
            "/mfa/setup" // MFA not enabled: setup required
        };

        let mut response = Html("").into_response();
        // SAFETY: redirect_url is a static string literal, always valid ASCII
        #[allow(clippy::expect_used)]
        let header_value =
            HeaderValue::from_str(redirect_url).expect("redirect URL is a valid header value");
        response.headers_mut().insert("HX-Redirect", header_value);
        return Ok((jar.add(cookie), response).into_response());
    }

    // API flow: handle MFA inline (legacy behavior for M2M compatibility)
    // Note: This is a temporary inconsistency - API users can bypass MFA setup requirement.
    // This will be addressed when MFA moves to vauban-auth service.
    let mfa_verified = if user.mfa_enabled {
        if let Some(code) = request.mfa_code {
            if let Some(secret) = &user.mfa_secret {
                // M-1: Verify TOTP via vault (encrypted secrets) or directly (plaintext, pre-migration)
                let valid = if let Some(ref vault) = state.vault_client
                    && is_encrypted(secret)
                {
                    vault
                        .mfa_verify(secret, &code)
                        .await
                        .map_err(|e| AppError::Auth(format!("MFA verification error: {}", e)))?
                } else {
                    // Direct verification: dev mode without vault, or plaintext secret (pre-migration)
                    AuthService::verify_totp(secret, &code)
                };
                if valid {
                    // Encrypt-on-read: progressively migrate plaintext MFA secrets
                    if let Some(ref vault) = state.vault_client
                        && !is_encrypted(secret)
                        && let Ok(encrypted) = vault.encrypt("mfa", secret).await
                    {
                        diesel::update(users.find(user.id))
                            .set(mfa_secret.eq(Some(&encrypted)))
                            .execute(&mut conn)
                            .await
                            .ok(); // Best-effort migration
                        tracing::info!(
                            user_id = user.id,
                            "Migrated plaintext MFA secret to encrypted (encrypt-on-read)"
                        );
                    }
                    true
                } else {
                    return Err(AppError::Auth("Invalid MFA code".to_string()));
                }
            } else {
                return Err(AppError::Auth("MFA configuration error".to_string()));
            }
        } else {
            // MFA required but no code provided
            return Ok(Json(LoginResponse {
                access_token: String::new(),
                refresh_token: String::new(),
                user: user.to_dto(),
                mfa_required: true,
            })
            .into_response());
        }
    } else {
        // MFA not enabled - API login proceeds without MFA
        // (temporary inconsistency: API users don't need to set up MFA)
        true
    };

    // Generate tokens (API flow with MFA verified)
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
        .await
        .map_err(AppError::Database)?;

    // Create auth session record for session management
    let token_hash = hash_token(&access_token);
    let trusted = state.config.security.parsed_trusted_proxies();
    let client_ip = extract_client_ip(&headers, client_addr, &trusted);
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
    .await
    .ok(); // Ignore errors - not critical

    // Insert new session
    // expires_at is set to session_max_duration_secs from config (absolute max lifetime)
    let new_session = NewAuthSession {
        uuid: ::uuid::Uuid::new_v4(),
        user_id: user.id,
        token_hash,
        ip_address: client_ip,
        user_agent: user_agent_str,
        device_info,
        expires_at: Utc::now()
            + Duration::seconds(state.config.security.session_max_duration_secs as i64),
        is_current: true,
    };

    let session_created = diesel::insert_into(auth_sessions::table)
        .values(&new_session)
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::warn!("Failed to create auth session: {}", e);
            e
        })
        .is_ok();

    // Broadcast session update to all connected WebSocket clients for this user
    if session_created {
        crate::handlers::web::broadcast_sessions_update(&state, &user.uuid.to_string(), user.id)
            .await;
    }

    // Set cookie
    use axum_extra::extract::cookie::{Cookie, SameSite};
    let cookie = Cookie::build(("access_token", access_token.clone()))
        .path("/")
        .http_only(true)
        .secure(true) // HTTPS-only app: always require secure cookies
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

/// Login handler for web UI (enforces CSRF).
pub async fn login_web(
    State(state): State<AppState>,
    client_addr: crate::middleware::ClientAddr,
    headers: HeaderMap,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> AppResult<Response> {
    let htmx = is_htmx_request(&headers);
    let secret = state.config.secret_key.expose_secret().as_bytes();
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    let csrf_value = request.csrf_token.as_deref().unwrap_or("");
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        csrf_value,
    ) {
        if htmx {
            return Ok(Html(login_error_html(LoginErrorKind::InvalidCsrf)).into_response());
        }
        return Err(AppError::Validation("Invalid CSRF token".to_string()));
    }
    login(State(state), client_addr, headers, jar, Json(request)).await
}

#[derive(Debug, Clone, Copy)]
enum LoginErrorKind {
    InvalidCredentials,
    AccountLocked,
    ValidationError,
    InvalidCsrf,
    RateLimited,
}

impl LoginErrorKind {
    fn message(self) -> &'static str {
        match self {
            Self::InvalidCredentials => "Invalid credentials",
            Self::AccountLocked => "Account is locked",
            Self::ValidationError => "Validation error",
            Self::InvalidCsrf => "Invalid CSRF token",
            Self::RateLimited => "Too many attempts. Please wait before trying again.",
        }
    }
}

/// Generate error HTML for HTMX login response.
fn login_error_html(kind: LoginErrorKind) -> String {
    let friendly = kind.message();
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
        friendly
    )
}

/// Hash a token using SHA3-256 for secure storage.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Determine progressive lockout duration based on failed attempts.
fn lockout_duration_for_attempts(failed_attempts: i32, threshold: u32) -> Option<Duration> {
    let threshold = threshold as i32;
    if failed_attempts < threshold {
        return None;
    }

    let stages = [
        Duration::minutes(5),
        Duration::minutes(15),
        Duration::hours(1),
        Duration::hours(24),
    ];
    let stage_index = (failed_attempts - threshold) as usize;
    Some(stages[stage_index.min(stages.len() - 1)])
}

/// Extract client IP from headers (X-Forwarded-For, X-Real-IP) or connection address.
///
/// Proxy headers are only trusted when the direct TCP connection originates from
/// an address listed in `trusted_proxies`.  This prevents spoofing of client IPs
/// by arbitrary clients injecting `X-Forwarded-For` / `X-Real-IP` headers.
fn extract_client_ip(
    headers: &HeaderMap,
    connect_addr: SocketAddr,
    trusted_proxies: &[std::net::IpAddr],
) -> IpNetwork {
    let resolved = crate::middleware::resolve_client_ip(
        headers,
        connect_addr.ip(),
        trusted_proxies,
    );
    IpNetwork::from(resolved)
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
        if let Ok(mut conn) = state.db_pool.get().await {
            // First, get the user info from the session before deleting
            let user_info: Option<(i32, ::uuid::Uuid)> = auth_sessions::table
                .inner_join(crate::schema::users::table)
                .filter(auth_sessions::token_hash.eq(&token_hash))
                .select((crate::schema::users::id, crate::schema::users::uuid))
                .first(&mut conn)
                .await
                .ok();

            // Delete session by token hash
            let deleted = diesel::delete(
                auth_sessions::table.filter(auth_sessions::token_hash.eq(&token_hash)),
            )
            .execute(&mut conn)
            .await
            .unwrap_or(0);

            // Broadcast session update to other connected clients
            if deleted > 0
                && let Some((user_id, user_uuid_val)) = user_info
            {
                crate::handlers::web::broadcast_sessions_update(
                    &state,
                    &user_uuid_val.to_string(),
                    user_id,
                )
                .await;
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

/// Logout handler for web UI (enforces CSRF).
///
/// If CSRF validation fails (e.g., expired session/cookie), we gracefully
/// redirect to login instead of showing an error. The user's intent is clear
/// and there's nothing to protect if the session is already expired.
pub async fn logout_web(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<AuthCsrfForm>,
) -> Response {
    let secret = state.config.secret_key.expose_secret().as_bytes();
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        // CSRF validation failed - likely expired session/cookie.
        // Gracefully redirect to login instead of showing an error.
        return Redirect::to("/login").into_response();
    }
    logout(State(state), jar).await
}

/// CSRF-only form payload for web auth routes.
#[derive(Debug, Deserialize)]
pub struct AuthCsrfForm {
    pub csrf_token: String,
}

// =============================================================================
// MFA Web Handlers (for human users)
// =============================================================================

use axum::response::Redirect;

/// Form for MFA code submission.
#[derive(Debug, Deserialize)]
pub struct MfaCodeForm {
    pub totp_code: String,
    pub csrf_token: String,
}

/// MFA setup page handler (GET /mfa/setup).
///
/// Displays the MFA setup page with QR code for users who haven't enabled MFA yet.
pub async fn mfa_setup_page(
    State(state): State<AppState>,
    jar: CookieJar,
    incoming_flash: IncomingFlash,
) -> AppResult<Response> {
    // Verify user is authenticated (via cookie)
    let token = jar
        .get("access_token")
        .map(|c| c.value().to_string())
        .ok_or_else(|| AppError::Auth("Not authenticated".to_string()))?;

    let claims = state.auth_service.verify_token(&token)?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Database connection error: {}", e)))?;
    use ::uuid::Uuid as UuidType;
    let user_uuid = UuidType::parse_str(&claims.sub)
        .map_err(|_| AppError::Validation("Invalid user UUID".to_string()))?;

    // Get user's current MFA secret (or generate new one)
    let user_data: (i32, String, Option<String>) = users
        .filter(uuid.eq(user_uuid))
        .filter(is_deleted.eq(false))
        .select((
            crate::schema::users::id,
            crate::schema::users::username,
            crate::schema::users::mfa_secret,
        ))
        .first(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let (user_id, user_username, existing_secret) = user_data;

    // Generate or use existing secret
    // M-1: When vault is available, secrets are encrypted at rest.
    // QR code is generated locally from the plaintext secret obtained from vault.
    let (secret, mut qr_code_base64) = if let Some(ref vault) = state.vault_client {
        if let Some(s) = existing_secret {
            if is_encrypted(&s) {
                // Get plaintext secret from vault (decrypt)
                let plaintext = vault.mfa_get_secret(&s).await.map_err(|e| {
                    AppError::Internal(anyhow::anyhow!("MFA secret decryption: {}", e))
                })?;
                let qr = AuthService::generate_totp_qr_code(
                    plaintext.as_str(),
                    &user_username,
                    "VAUBAN",
                )?;
                // plaintext (SensitiveString) zeroized on drop here
                (s, qr)
            } else {
                // Plaintext secret (pre-migration): encrypt-on-read, then generate QR
                let encrypted = vault.encrypt("mfa", &s).await.map_err(|e| {
                    AppError::Internal(anyhow::anyhow!("MFA encryption: {}", e))
                })?;
                diesel::update(users.filter(crate::schema::users::id.eq(user_id)))
                    .set(mfa_secret.eq(Some(&encrypted)))
                    .execute(&mut conn)
                    .await
                    .map_err(AppError::Database)?;
                tracing::info!(
                    user_id,
                    "Migrated plaintext MFA secret to encrypted (encrypt-on-read)"
                );
                // Get plaintext back from vault to generate QR
                let plaintext = vault.mfa_get_secret(&encrypted).await.map_err(|e| {
                    AppError::Internal(anyhow::anyhow!("MFA secret decryption: {}", e))
                })?;
                let qr = AuthService::generate_totp_qr_code(
                    plaintext.as_str(),
                    &user_username,
                    "VAUBAN",
                )?;
                // plaintext (SensitiveString) zeroized on drop here
                (encrypted, qr)
            }
        } else {
            // Generate new secret via vault
            let (encrypted_secret, plaintext) = vault
                .mfa_generate(&user_username, "VAUBAN")
                .await
                .map_err(|e| AppError::Internal(anyhow::anyhow!("MFA generation: {}", e)))?;
            let qr = AuthService::generate_totp_qr_code(
                plaintext.as_str(),
                &user_username,
                "VAUBAN",
            )?;
            // plaintext (SensitiveString) zeroized on drop here
            diesel::update(users.filter(crate::schema::users::id.eq(user_id)))
                .set(mfa_secret.eq(Some(&encrypted_secret)))
                .execute(&mut conn)
                .await
                .map_err(AppError::Database)?;
            (encrypted_secret, qr)
        }
    } else {
        // Fallback: direct generation (dev mode without vault)
        let secret = if let Some(s) = existing_secret {
            s
        } else {
            let (new_secret, _uri) = AuthService::generate_totp_secret(&user_username, "VAUBAN")?;
            diesel::update(users.filter(crate::schema::users::id.eq(user_id)))
                .set(mfa_secret.eq(Some(&new_secret)))
                .execute(&mut conn)
                .await
                .map_err(AppError::Database)?;
            new_secret
        };
        let qr = AuthService::generate_totp_qr_code(&secret, &user_username, "VAUBAN")?;
        (secret, qr)
    };

    // Build template without sidebar (user not fully authenticated yet)
    // Convert incoming flash messages to template FlashMessages
    let flash_messages: Vec<crate::templates::base::FlashMessage> = incoming_flash
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect();
    let base = BaseTemplate::new("MFA Setup".to_string(), None).with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = MfaSetupTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        secret,
        qr_code_base64: qr_code_base64.clone(),
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    // Zeroize QR code data after template rendering (contains TOTP secret in image)
    qr_code_base64.zeroize();
    Ok(Html(html).into_response())
}

/// MFA setup submit handler (POST /mfa/setup).
///
/// Validates the TOTP code and enables MFA for the user.
pub async fn mfa_setup_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    incoming_flash: IncomingFlash,
    Form(form): Form<MfaCodeForm>,
) -> AppResult<Response> {
    let flash = incoming_flash.flash();

    // Validate CSRF
    let secret_key = state.config.secret_key.expose_secret().as_bytes();
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        secret_key,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return Ok(flash_redirect(
            flash.error("Invalid CSRF token"),
            "/mfa/setup",
        ));
    }

    // Verify user is authenticated
    let token = jar
        .get("access_token")
        .map(|c| c.value().to_string())
        .ok_or_else(|| AppError::Auth("Not authenticated".to_string()))?;

    let claims = state.auth_service.verify_token(&token)?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Database connection error: {}", e)))?;
    use ::uuid::Uuid as UuidType;
    let user_uuid = UuidType::parse_str(&claims.sub)
        .map_err(|_| AppError::Validation("Invalid user UUID".to_string()))?;

    // Get user's MFA secret
    let user_data: (i32, String, Option<String>, bool, bool) = users
        .filter(uuid.eq(user_uuid))
        .filter(is_deleted.eq(false))
        .select((
            crate::schema::users::id,
            crate::schema::users::username,
            crate::schema::users::mfa_secret,
            crate::schema::users::is_superuser,
            crate::schema::users::is_staff,
        ))
        .first(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let (user_id, user_username, secret_opt, is_super, is_staff_user) = user_data;

    let secret =
        secret_opt.ok_or_else(|| AppError::Internal(anyhow::anyhow!("MFA secret not found")))?;

    // Validate TOTP code
    // M-1: Verify via vault when available (encrypted secrets), or directly (plaintext, pre-migration)
    let code = form.totp_code.trim();
    let valid = if let Some(ref vault) = state.vault_client
        && is_encrypted(&secret)
    {
        vault.mfa_verify(&secret, code).await.unwrap_or(false)
    } else {
        AuthService::verify_totp(&secret, code)
    };
    if !valid {
        return Ok(flash_redirect(
            flash.error("Invalid verification code. Please try again."),
            "/mfa/setup",
        ));
    }

    // Encrypt-on-read: progressively migrate plaintext MFA secrets
    if let Some(ref vault) = state.vault_client
        && !is_encrypted(&secret)
        && let Ok(encrypted) = vault.encrypt("mfa", &secret).await
    {
        diesel::update(users.filter(crate::schema::users::id.eq(user_id)))
            .set(mfa_secret.eq(Some(&encrypted)))
            .execute(&mut conn)
            .await
            .ok(); // Best-effort migration
        tracing::info!(
            user_id,
            "Migrated plaintext MFA secret to encrypted (encrypt-on-read)"
        );
    }

    // Enable MFA for user
    diesel::update(users.filter(crate::schema::users::id.eq(user_id)))
        .set((
            crate::schema::users::mfa_enabled.eq(true),
            crate::schema::users::updated_at.eq(chrono::Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .map_err(AppError::Database)?;

    // Generate new JWT with mfa_verified = true
    let new_token = state.auth_service.generate_access_token(
        &claims.sub,
        &user_username,
        true, // mfa_verified
        is_super,
        is_staff_user,
    )?;

    // Update the session in database with new token hash
    // The old token hash won't work anymore, we need to update to the new one
    let old_token_hash = hash_token(&token);
    let new_token_hash = hash_token(&new_token);

    diesel::update(auth_sessions::table.filter(auth_sessions::token_hash.eq(&old_token_hash)))
        .set(auth_sessions::token_hash.eq(&new_token_hash))
        .execute(&mut conn)
        .await
        .ok(); // Ignore errors - session will be recreated on next login if needed

    // Set new cookie
    use axum_extra::extract::cookie::{Cookie, SameSite};
    let cookie = Cookie::build(("access_token", new_token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();

    Ok((
        jar.add(cookie),
        flash_redirect(
            flash.success("Two-factor authentication has been enabled successfully."),
            "/dashboard",
        ),
    )
        .into_response())
}

/// MFA verify page handler (GET /mfa/verify).
///
/// Displays the MFA verification page for users who have MFA enabled.
pub async fn mfa_verify_page(
    State(state): State<AppState>,
    jar: CookieJar,
    incoming_flash: IncomingFlash,
) -> AppResult<Response> {
    // Verify user is authenticated (via cookie)
    let token = jar
        .get("access_token")
        .map(|c| c.value().to_string())
        .ok_or_else(|| AppError::Auth("Not authenticated".to_string()))?;

    let _claims = state.auth_service.verify_token(&token)?;

    // Build template without sidebar (user not fully authenticated yet)
    // Convert incoming flash messages to template FlashMessages
    let flash_messages: Vec<crate::templates::base::FlashMessage> = incoming_flash
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect();
    let base = BaseTemplate::new("Verify Identity".to_string(), None).with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = MfaVerifyTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html).into_response())
}

/// MFA verify submit handler (POST /mfa/verify).
///
/// Validates the TOTP code and completes authentication.
pub async fn mfa_verify_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    incoming_flash: IncomingFlash,
    Form(form): Form<MfaCodeForm>,
) -> AppResult<Response> {
    let flash = incoming_flash.flash();

    // Validate CSRF
    let secret_key = state.config.secret_key.expose_secret().as_bytes();
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        secret_key,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return Ok(flash_redirect(
            flash.error("Invalid CSRF token"),
            "/mfa/verify",
        ));
    }

    // Verify user is authenticated
    let token = jar
        .get("access_token")
        .map(|c| c.value().to_string())
        .ok_or_else(|| AppError::Auth("Not authenticated".to_string()))?;

    let claims = state.auth_service.verify_token(&token)?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Database connection error: {}", e)))?;
    use ::uuid::Uuid as UuidType;
    let user_uuid = UuidType::parse_str(&claims.sub)
        .map_err(|_| AppError::Validation("Invalid user UUID".to_string()))?;

    // Get user's MFA secret (includes user_id for encrypt-on-read migration)
    let user_data: (i32, String, Option<String>, bool, bool) = users
        .filter(uuid.eq(user_uuid))
        .filter(is_deleted.eq(false))
        .select((
            crate::schema::users::id,
            crate::schema::users::username,
            crate::schema::users::mfa_secret,
            crate::schema::users::is_superuser,
            crate::schema::users::is_staff,
        ))
        .first(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let (user_id, user_username, secret_opt, is_super, is_staff_user) = user_data;

    let secret =
        secret_opt.ok_or_else(|| AppError::Internal(anyhow::anyhow!("MFA secret not found")))?;

    // Validate TOTP code
    // M-1: Verify via vault when available (encrypted secrets), or directly (plaintext, pre-migration)
    let code = form.totp_code.trim();
    let valid = if let Some(ref vault) = state.vault_client
        && is_encrypted(&secret)
    {
        vault.mfa_verify(&secret, code).await.unwrap_or(false)
    } else {
        AuthService::verify_totp(&secret, code)
    };
    if !valid {
        return Ok(flash_redirect(
            flash.error("Invalid verification code. Please try again."),
            "/mfa/verify",
        ));
    }

    // Encrypt-on-read: progressively migrate plaintext MFA secrets
    if let Some(ref vault) = state.vault_client
        && !is_encrypted(&secret)
        && let Ok(encrypted) = vault.encrypt("mfa", &secret).await
    {
        diesel::update(users.filter(crate::schema::users::id.eq(user_id)))
            .set(mfa_secret.eq(Some(&encrypted)))
            .execute(&mut conn)
            .await
            .ok(); // Best-effort migration
        tracing::info!(
            user_id,
            "Migrated plaintext MFA secret to encrypted (encrypt-on-read)"
        );
    }

    // Generate new JWT with mfa_verified = true
    let new_token = state.auth_service.generate_access_token(
        &claims.sub,
        &user_username,
        true, // mfa_verified
        is_super,
        is_staff_user,
    )?;

    // Update the session in database with new token hash
    // The old token hash won't work anymore, we need to update to the new one
    let old_token_hash = hash_token(&token);
    let new_token_hash = hash_token(&new_token);

    diesel::update(auth_sessions::table.filter(auth_sessions::token_hash.eq(&old_token_hash)))
        .set(auth_sessions::token_hash.eq(&new_token_hash))
        .execute(&mut conn)
        .await
        .ok(); // Ignore errors - session will be recreated on next login if needed

    // Set new cookie
    use axum_extra::extract::cookie::{Cookie, SameSite};
    let cookie = Cookie::build(("access_token", new_token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();

    Ok((jar.add(cookie), Redirect::to("/dashboard")).into_response())
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
            csrf_token: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_login_request_short_username() {
        let request = LoginRequest {
            username: "ab".to_string(), // Too short (min 3)
            password: "validpassword123".to_string(),
            mfa_code: None,
            csrf_token: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_login_request_short_password() {
        let request = LoginRequest {
            username: "validuser".to_string(),
            password: "short".to_string(), // Too short (min 12)
            mfa_code: None,
            csrf_token: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_login_request_with_mfa_code() {
        let request = LoginRequest {
            username: "validuser".to_string(),
            password: "validpassword123".to_string(),
            mfa_code: Some("123456".to_string()),
            csrf_token: None,
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
            csrf_token: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_login_request_password_minimum_length() {
        let request = LoginRequest {
            username: "validuser".to_string(),
            password: "123456789012".to_string(), // Exactly 12 chars
            mfa_code: None,
            csrf_token: None,
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

        let json = unwrap_ok!(serde_json::to_string(&response));

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

        let json = unwrap_ok!(serde_json::to_string(&response));
        let parsed: serde_json::Value = unwrap_ok!(serde_json::from_str(&json));

        assert_eq!(parsed["mfa_required"], true);
    }

    // ==================== extract_client_ip Tests ====================

    #[test]
    fn test_extract_client_ip_from_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            unwrap_ok!("203.0.113.50, 70.41.3.18, 150.172.238.178".parse()),
        );

        let fallback_addr: SocketAddr = unwrap_ok!("192.168.1.1:12345".parse());
        // Connection from trusted proxy -> XFF honoured
        let trusted = vec![unwrap_ok!("192.168.1.1".parse())];
        let ip = extract_client_ip(&headers, fallback_addr, &trusted);

        assert_eq!(ip.ip().to_string(), "203.0.113.50");
    }

    #[test]
    fn test_extract_client_ip_xff_ignored_untrusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            unwrap_ok!("203.0.113.50".parse()),
        );

        let fallback_addr: SocketAddr = unwrap_ok!("192.168.1.1:12345".parse());
        // Connection NOT from trusted proxy -> XFF ignored
        let ip = extract_client_ip(&headers, fallback_addr, &[]);

        assert_eq!(ip.ip().to_string(), "192.168.1.1");
    }

    #[test]
    fn test_extract_client_ip_from_x_forwarded_for_single() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", unwrap_ok!("8.8.8.8".parse()));

        let fallback_addr: SocketAddr = unwrap_ok!("192.168.1.1:12345".parse());
        let trusted = vec![unwrap_ok!("192.168.1.1".parse())];
        let ip = extract_client_ip(&headers, fallback_addr, &trusted);

        assert_eq!(ip.ip().to_string(), "8.8.8.8");
    }

    #[test]
    fn test_extract_client_ip_from_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", unwrap_ok!("1.2.3.4".parse()));

        let fallback_addr: SocketAddr = unwrap_ok!("192.168.1.1:12345".parse());
        let trusted = vec![unwrap_ok!("192.168.1.1".parse())];
        let ip = extract_client_ip(&headers, fallback_addr, &trusted);

        assert_eq!(ip.ip().to_string(), "1.2.3.4");
    }

    #[test]
    fn test_extract_client_ip_x_forwarded_for_takes_priority() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", unwrap_ok!("203.0.113.50".parse()));
        headers.insert("X-Real-IP", unwrap_ok!("1.2.3.4".parse()));

        let fallback_addr: SocketAddr = unwrap_ok!("192.168.1.1:12345".parse());
        let trusted = vec![unwrap_ok!("192.168.1.1".parse())];
        let ip = extract_client_ip(&headers, fallback_addr, &trusted);

        assert_eq!(ip.ip().to_string(), "203.0.113.50");
    }

    #[test]
    fn test_extract_client_ip_fallback_to_connect_addr() {
        let headers = HeaderMap::new(); // No proxy headers

        let fallback_addr: SocketAddr = unwrap_ok!("85.123.45.67:54321".parse());
        let ip = extract_client_ip(&headers, fallback_addr, &[]);

        assert_eq!(ip.ip().to_string(), "85.123.45.67");
    }

    #[test]
    fn test_extract_client_ip_ipv6() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", unwrap_ok!("2001:db8::1".parse()));

        let fallback_addr: SocketAddr = unwrap_ok!("[::1]:12345".parse());
        let trusted = vec![unwrap_ok!("::1".parse())];
        let ip = extract_client_ip(&headers, fallback_addr, &trusted);

        assert_eq!(ip.ip().to_string(), "2001:db8::1");
    }

    #[test]
    fn test_extract_client_ip_fallback_ipv6() {
        let headers = HeaderMap::new();

        let fallback_addr: SocketAddr = unwrap_ok!("[2001:db8::abcd]:443".parse());
        let ip = extract_client_ip(&headers, fallback_addr, &[]);

        assert_eq!(ip.ip().to_string(), "2001:db8::abcd");
    }

    #[test]
    fn test_extract_client_ip_invalid_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", unwrap_ok!("not-an-ip-address".parse()));

        let fallback_addr: SocketAddr = unwrap_ok!("10.0.0.1:8080".parse());
        let trusted = vec![unwrap_ok!("10.0.0.1".parse())];
        let ip = extract_client_ip(&headers, fallback_addr, &trusted);

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

    // ==================== hash_token Additional Tests ====================

    #[test]
    fn test_hash_token_empty() {
        let hash = hash_token("");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_token_unicode() {
        let hash = hash_token("密码测试🔐");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hash_token_long_input() {
        let long_token = "a".repeat(10000);
        let hash = hash_token(&long_token);
        assert_eq!(hash.len(), 64);
    }

    // ==================== extract_client_ip Additional Tests ====================

    #[test]
    fn test_extract_client_ip_xff_with_spaces() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            unwrap_ok!("  1.2.3.4  , 5.6.7.8".parse()),
        );

        let fallback: SocketAddr = unwrap_ok!("10.0.0.1:8080".parse());
        let trusted = vec![unwrap_ok!("10.0.0.1".parse())];
        let ip = extract_client_ip(&headers, fallback, &trusted);

        assert_eq!(ip.ip().to_string(), "1.2.3.4");
    }

    #[test]
    fn test_extract_client_ip_xff_ipv6_mixed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            unwrap_ok!("::ffff:192.168.1.1, 10.0.0.1".parse()),
        );

        let fallback: SocketAddr = unwrap_ok!("127.0.0.1:8080".parse());
        let trusted = vec![unwrap_ok!("127.0.0.1".parse())];
        let ip = extract_client_ip(&headers, fallback, &trusted);

        assert!(
            ip.ip().to_string().contains("192.168.1.1") || ip.ip().to_string().contains("ffff")
        );
    }

    #[test]
    fn test_extract_client_ip_x_real_ip_invalid_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", unwrap_ok!("not-valid".parse()));

        let fallback: SocketAddr = unwrap_ok!("172.16.0.1:443".parse());
        let trusted = vec![unwrap_ok!("172.16.0.1".parse())];
        let ip = extract_client_ip(&headers, fallback, &trusted);

        assert_eq!(ip.ip().to_string(), "172.16.0.1");
    }

    #[test]
    fn test_extract_client_ip_localhost() {
        let headers = HeaderMap::new();

        let fallback: SocketAddr = unwrap_ok!("127.0.0.1:3000".parse());
        let ip = extract_client_ip(&headers, fallback, &[]);

        assert_eq!(ip.ip().to_string(), "127.0.0.1");
    }

    // ==================== is_htmx_request Tests ====================

    #[test]
    fn test_is_htmx_request_true() {
        let mut headers = HeaderMap::new();
        headers.insert("HX-Request", unwrap_ok!("true".parse()));

        assert!(is_htmx_request(&headers));
    }

    #[test]
    fn test_is_htmx_request_false() {
        let headers = HeaderMap::new();
        assert!(!is_htmx_request(&headers));
    }

    #[test]
    fn test_is_htmx_request_any_value() {
        let mut headers = HeaderMap::new();
        headers.insert("HX-Request", unwrap_ok!("1".parse()));

        // Any value should be considered true (just presence check)
        assert!(is_htmx_request(&headers));
    }

    // ==================== login_error_html Tests ====================

    #[test]
    fn test_login_error_html_contains_message() {
        let html = login_error_html(LoginErrorKind::InvalidCredentials);

        assert!(html.contains("Invalid credentials"));
        assert!(html.contains("login-result"));
        assert!(html.contains("bg-red-50"));
    }

    #[test]
    fn test_login_error_html_account_locked_message() {
        let html = login_error_html(LoginErrorKind::AccountLocked);

        assert!(html.contains("Account is locked"));
        assert!(html.contains("login-result"));
    }

    #[test]
    fn test_login_error_html_validation_message() {
        let html = login_error_html(LoginErrorKind::ValidationError);

        assert!(html.contains("Validation error"));
        assert!(html.contains("login-result"));
    }

    // ==================== lockout_duration_for_attempts Tests ====================

    #[test]
    fn test_lockout_duration_below_threshold() {
        let duration = lockout_duration_for_attempts(2, 3);
        assert!(duration.is_none());
    }

    #[test]
    fn test_lockout_duration_first_stage() {
        let duration = unwrap_some!(lockout_duration_for_attempts(3, 3));
        assert_eq!(duration, Duration::minutes(5));
    }

    #[test]
    fn test_lockout_duration_progressive_stages() {
        assert_eq!(
            unwrap_some!(lockout_duration_for_attempts(4, 3)),
            Duration::minutes(15)
        );
        assert_eq!(
            unwrap_some!(lockout_duration_for_attempts(5, 3)),
            Duration::hours(1)
        );
        assert_eq!(
            unwrap_some!(lockout_duration_for_attempts(6, 3)),
            Duration::hours(24)
        );
        assert_eq!(
            unwrap_some!(lockout_duration_for_attempts(10, 3)),
            Duration::hours(24)
        );
    }

    // ==================== LoginRequest Debug Tests ====================

    #[test]
    fn test_login_request_debug_redacts_password() {
        let request = LoginRequest {
            username: "testuser".to_string(),
            password: "securepassword".to_string(),
            mfa_code: Some("123456".to_string()),
            csrf_token: None,
        };

        let debug_str = format!("{:?}", request);

        assert!(debug_str.contains("LoginRequest"));
        assert!(debug_str.contains("testuser"));
        // Password and mfa_code MUST be redacted (H-4)
        assert!(
            !debug_str.contains("securepassword"),
            "Password must not appear in Debug output"
        );
        assert!(
            !debug_str.contains("123456"),
            "MFA code must not appear in Debug output"
        );
        assert!(debug_str.contains("[REDACTED]"));
    }

    // ==================== LoginResponse Debug Tests ====================

    #[test]
    fn test_login_response_debug() {
        let user_dto = crate::models::user::UserDto {
            uuid: ::uuid::Uuid::new_v4(),
            username: "debuguser".to_string(),
            email: "debug@test.com".to_string(),
            first_name: None,
            last_name: None,
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
            access_token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            user: user_dto,
            mfa_required: false,
        };

        let debug_str = format!("{:?}", response);
        assert!(debug_str.contains("LoginResponse"));
    }

    // ==================== Validation Edge Cases ====================

    #[test]
    fn test_login_request_boundary_username() {
        // Exactly at minimum length
        let request = LoginRequest {
            username: "abc".to_string(),
            password: "123456789012".to_string(),
            mfa_code: None,
            csrf_token: None,
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_login_request_unicode_username() {
        let request = LoginRequest {
            username: "用户名".to_string(), // 3 unicode chars
            password: "validpassword123".to_string(),
            mfa_code: None,
            csrf_token: None,
        };
        // Unicode chars count as 1 each
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_login_request_unicode_password() {
        let request = LoginRequest {
            username: "testuser".to_string(),
            password: "密码测试密码测试密码测试".to_string(), // 12 unicode chars
            mfa_code: None,
            csrf_token: None,
        };
        assert!(request.validate().is_ok());
    }

    // ==================== is_encrypted Tests (backward compat) ====================

    #[test]
    fn test_is_encrypted_valid_formats() {
        assert!(is_encrypted("v1:SGVsbG8="));
        assert!(is_encrypted("v12:AAAA"));
        assert!(is_encrypted("v999:longbase64data"));
    }

    #[test]
    fn test_is_encrypted_plaintext_totp_secrets() {
        // Base32-encoded TOTP secrets (the format used before encryption)
        assert!(!is_encrypted("JBSWY3DPEHPK3PXP"));
        assert!(!is_encrypted("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert!(!is_encrypted("MFZWIZLTOQ======"));
    }

    #[test]
    fn test_is_encrypted_invalid_formats() {
        assert!(!is_encrypted(""));
        assert!(!is_encrypted("abc"));
        assert!(!is_encrypted("v:data")); // no version number
        assert!(!is_encrypted("v1data")); // no colon
        assert!(!is_encrypted("va:data")); // non-digit version
        assert!(!is_encrypted("plaintext-password"));
    }

    #[test]
    fn test_is_encrypted_edge_cases() {
        // Minimum valid format
        assert!(is_encrypted("v1:x"));
        // Version 0 is technically valid format (but would fail at keyring level)
        assert!(is_encrypted("v0:x"));
        // Very large version number
        assert!(is_encrypted("v12345:data"));
    }
}
