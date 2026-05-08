/// VAUBAN Web - Authentication handlers.
///
/// Login, logout, MFA setup and verification.
use axum::{
    Json,
    extract::{Form, State},
    http::{HeaderValue, StatusCode, header::HeaderMap},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel::OptionalExtension;
use diesel_async::RunQueryDsl;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use validator::Validate;
use zeroize::Zeroize;

use askama::Template;

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::browser_tz::BrowserTz;
use crate::middleware::flash::{IncomingFlash, flash_redirect};
use crate::models::auth_session::{AuthSession, NewAuthSession};
#[cfg(test)]
use crate::models::user::AuthSource;
use crate::models::user::User;
use crate::schema::{auth_sessions, users::dsl::*};
use crate::services::auth::{AuthService, Claims, is_encrypted_mfa_secret};
use crate::templates::accounts::{MfaSetupTemplate, MfaVerifyTemplate};
use crate::templates::base::BaseTemplate;

/// Local alias preserved so the call sites below stay readable. The actual
/// classification logic lives in [`crate::services::auth::is_encrypted_mfa_secret`]
/// so the login flow and the step-up flow ([`crate::auth::step_up`]) stay in
/// lockstep -- a divergence here is exactly what shipped issue #11.
#[inline]
fn is_encrypted(value: &str) -> bool {
    is_encrypted_mfa_secret(value)
}

// is_htmx_request deduplicated - use crate::error::is_htmx_request
use crate::error::is_htmx_request;

/// Login request.
///
/// `Debug` is manually implemented to redact the `password` and `mfa_code`
/// fields, preventing accidental credential leaks in logs.
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
        return rate_limit_response(htmx, rate_result.reset_in_secs);
    }

    // Validation -- return the same generic error as invalid credentials
    // to prevent password policy enumeration (SEC-05).
    if validator::Validate::validate(&request).is_err() {
        return login_error_response(htmx, LoginErrorKind::InvalidCredentials);
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
            return login_error_response(htmx, LoginErrorKind::InvalidCredentials);
        }
    };

    // SEC-04: verify password BEFORE checking account state to prevent
    // enumeration via lockout/deactivation differential responses.
    let password_valid = if let Some(ref client) = state.auth_ipc_client {
        client
            .verify_password(&request.password, &user.password_hash)
            .await?
    } else {
        state
            .auth_service
            .verify_password(&request.password, &user.password_hash)?
    };
    if !password_valid {
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

        // SEC-04: always return generic "Invalid credentials" regardless of
        // whether lockout was triggered, to prevent account enumeration.
        return login_error_response(htmx, LoginErrorKind::InvalidCredentials);
    }

    // SEC-04: account state checks after password verification -- an attacker
    // with an invalid password only ever sees "Invalid credentials".
    if user.is_locked() || !user.is_active {
        return login_error_response(htmx, LoginErrorKind::InvalidCredentials);
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

        let session_uuid = ::uuid::Uuid::new_v4();
        // Generate temporary token with mfa_verified = false
        let temp_token = state.auth_service.generate_access_token(
            &user.uuid.to_string(),
            &user.username,
            false, // mfa_verified = false
            // allow-role-gate: passed as JWT claim so the request-scoped Casbin subject mapping works on subsequent requests.
            user.is_superuser,
            // allow-role-gate: passed as JWT claim so the request-scoped Casbin subject mapping works on subsequent requests.
            user.is_staff,
            Some(session_uuid),
        )?;

        // Create auth session with temporary token
        let token_hash = hash_token(&temp_token);
        let trusted = state.config.security.parsed_trusted_proxies();
        let client_ip = extract_client_ip(&headers, client_addr, &trusted);
        let user_agent_str = headers
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        // Issue #8: `device_info` is now NOT NULL in the DB so we resolve
        // the User-Agent eagerly (or fall back to the same sentinel as the
        // SQL default) to keep the (user, device, IP) fingerprint
        // deterministic for the UNIQUE index.
        let device_info_str = user_agent_str
            .as_deref()
            .map(AuthSession::parse_device_info)
            .unwrap_or_else(|| "Unknown browser".to_string());

        // Insert new session inside a transaction that first purges any
        // prior session for the same (user, device, IP) -- see Issue #8
        // and `insert_session_with_purge`. expires_at is set to
        // session_max_duration_secs from config (absolute max lifetime).
        let new_session = NewAuthSession {
            uuid: session_uuid,
            user_id: user.id,
            token_hash,
            ip_address: client_ip,
            user_agent: user_agent_str,
            device_info: device_info_str.clone(),
            expires_at: Utc::now()
                + Duration::seconds(state.config.security.session_max_duration_secs as i64),
            is_current: true,
        };

        let session_created = match insert_session_with_purge(
            &mut conn,
            user.id,
            device_info_str,
            client_ip,
            new_session,
        )
        .await
        {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("Failed to create auth session: {}", e);
                false
            }
        };

        if session_created {
            crate::handlers::web::broadcast_sessions_update(
                &state,
                &user.uuid.to_string(),
                user.id,
            )
            .await;
            crate::handlers::web::broadcast_admin_sessions_update(&state).await;
        }

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

    // SECURITY (Finding #2 remediation): MFA is mandatory for API login.
    //
    // Previously, accounts without MFA configured received a fully trusted
    // session token from this endpoint -- a policy bypass for a bastion
    // that mints credentials for privileged access. We now fail closed:
    // if MFA is not enabled on the account, the API refuses the login and
    // directs the caller to the web flow (which walks the user through
    // TOTP enrolment via `/mfa/setup`). Service accounts that need M2M
    // auth must use a dedicated mechanism (API keys or mTLS), not this
    // password endpoint.
    if !user.mfa_enabled {
        tracing::warn!(
            user_id = user.id,
            username = %user.username,
            "API login refused: MFA not configured for account"
        );
        return Err(AppError::Authorization(
            "MFA setup is required before API login. Please complete MFA enrolment via \
             the web interface at /mfa/setup, then retry."
                .to_string(),
        ));
    }

    // From here we know MFA is enabled. Verify the TOTP code.
    let mfa_verified = if let Some(code) = request.mfa_code {
        if let Some(secret) = &user.mfa_secret {
            // Issue #11 hardening: refuse explicitly when the secret is
            // encrypted (vault envelope) but the vault IPC is not
            // available -- otherwise we would silently call
            // `verify_totp` on the ciphertext and return "Invalid MFA
            // code" forever.
            if is_encrypted(secret) && state.vault_client.is_none() {
                tracing::error!(
                    user_id = user.id,
                    "API login MFA: secret is encrypted but vault client is not configured"
                );
                return Err(AppError::Auth(
                    "MFA backend is temporarily unavailable.".to_string(),
                ));
            }
            // Verify TOTP via vault (encrypted secrets) or directly (plaintext, pre-migration)
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
            // mfa_enabled=true but no secret -- corrupted state
            tracing::error!(
                user_id = user.id,
                "MFA configuration inconsistency: mfa_enabled=true but mfa_secret is NULL"
            );
            return Err(AppError::Auth("MFA configuration error".to_string()));
        }
    } else {
        // MFA enabled but no code provided: surface as `mfa_required`.
        // Note: the response carries no token -- the client must replay the
        // login with the TOTP code in `mfa_code` to receive one.
        return Ok(Json(LoginResponse {
            access_token: String::new(),
            refresh_token: String::new(),
            user: user.to_dto(),
            mfa_required: true,
        })
        .into_response());
    };

    let session_uuid = ::uuid::Uuid::new_v4();
    // Generate tokens (API flow with MFA verified)
    let access_token = state.auth_service.generate_access_token(
        &user.uuid.to_string(),
        &user.username,
        mfa_verified,
        // allow-role-gate: passed as JWT claim so the request-scoped Casbin subject mapping works on subsequent requests.
        user.is_superuser,
        // allow-role-gate: passed as JWT claim so the request-scoped Casbin subject mapping works on subsequent requests.
        user.is_staff,
        Some(session_uuid),
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
    // Issue #8: same fingerprint normalisation as the web flow above.
    let device_info_str = user_agent_str
        .as_deref()
        .map(AuthSession::parse_device_info)
        .unwrap_or_else(|| "Unknown browser".to_string());

    // Insert new session inside a transaction that first purges any prior
    // session for the same (user, device, IP) -- see Issue #8 and
    // `insert_session_with_purge`. expires_at is set to
    // session_max_duration_secs from config (absolute max lifetime).
    let new_session = NewAuthSession {
        uuid: session_uuid,
        user_id: user.id,
        token_hash,
        ip_address: client_ip,
        user_agent: user_agent_str,
        device_info: device_info_str.clone(),
        expires_at: Utc::now()
            + Duration::seconds(state.config.security.session_max_duration_secs as i64),
        is_current: true,
    };

    let session_created = match insert_session_with_purge(
        &mut conn,
        user.id,
        device_info_str,
        client_ip,
        new_session,
    )
    .await
    {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!("Failed to create auth session: {}", e);
            false
        }
    };

    // Broadcast session update to all connected WebSocket clients for this user
    if session_created {
        crate::handlers::web::broadcast_sessions_update(&state, &user.uuid.to_string(), user.id)
            .await;
        crate::handlers::web::broadcast_admin_sessions_update(&state).await;
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
        return login_error_response(htmx, LoginErrorKind::InvalidCsrf);
    }
    login(State(state), client_addr, headers, jar, Json(request)).await
}

#[derive(Debug, Clone, Copy)]
enum LoginErrorKind {
    InvalidCredentials,
    InvalidCsrf,
    RateLimited,
}

impl LoginErrorKind {
    fn message(self) -> &'static str {
        match self {
            Self::InvalidCredentials => "Invalid credentials",
            Self::InvalidCsrf => "Invalid or expired form. Please reload and try again.",
            Self::RateLimited => "Too many attempts. Please wait before trying again.",
        }
    }
}

fn login_error_html(kind: LoginErrorKind) -> String {
    format!(
        r#"<div id="login-result" class="rounded-md bg-red-50 dark:bg-red-900/50 p-4">{}</div>"#,
        crate::error::html_error_fragment(kind.message())
    )
}

fn login_error_response(htmx: bool, kind: LoginErrorKind) -> AppResult<Response> {
    if htmx {
        Ok(Html(login_error_html(kind)).into_response())
    } else {
        Err(AppError::Auth(kind.message().to_string()))
    }
}

fn rate_limit_response(htmx: bool, reset_in_secs: u64) -> AppResult<Response> {
    if htmx {
        return Ok(Html(login_error_html(LoginErrorKind::RateLimited)).into_response());
    }
    Ok((
        StatusCode::TOO_MANY_REQUESTS,
        [
            ("Retry-After", reset_in_secs.to_string()),
            ("X-RateLimit-Remaining", "0".to_string()),
        ],
        Json(serde_json::json!({
            "error": LoginErrorKind::RateLimited.message(),
            "retry_after": reset_in_secs
        })),
    )
        .into_response())
}

/// Hash a token using SHA3-256 for secure storage.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

async fn resolve_auth_session_uuid(
    conn: &mut diesel_async::AsyncPgConnection,
    claims: &Claims,
    current_token: &str,
) -> Result<Option<::uuid::Uuid>, diesel::result::Error> {
    if let Some(ref jti) = claims.jti
        && let Ok(u) = ::uuid::Uuid::parse_str(jti)
    {
        return Ok(Some(u));
    }
    let old_hash = hash_token(current_token);
    auth_sessions::table
        .filter(auth_sessions::token_hash.eq(old_hash))
        .select(auth_sessions::uuid)
        .first(conn)
        .await
        .optional()
}

/// Issue #8: enforce at most one live `auth_sessions` row per
/// `(user_id, device_info, ip_address)` fingerprint.
///
/// Called inside the same DB transaction as the INSERT of a new session,
/// so concurrent logins for the same fingerprint cannot both win the
/// race -- the loser will either re-purge or trip the
/// `uniq_auth_sessions_per_device` UNIQUE index and be retried by
/// [`insert_session_with_purge`].
async fn purge_sessions_for_device(
    conn: &mut diesel_async::AsyncPgConnection,
    user_id_val: i32,
    device: &str,
    client_ip: ipnetwork::IpNetwork,
) -> Result<usize, diesel::result::Error> {
    let deleted = diesel::delete(
        auth_sessions::table
            .filter(auth_sessions::user_id.eq(user_id_val))
            .filter(auth_sessions::device_info.eq(device))
            .filter(auth_sessions::ip_address.eq(client_ip)),
    )
    .execute(conn)
    .await?;
    if deleted > 0 {
        tracing::info!(
            user_id = user_id_val,
            deleted,
            device = %device,
            "Purged superseded login sessions for device on new login"
        );
    }
    Ok(deleted)
}

/// Issue #8: insert a new `auth_sessions` row while enforcing the
/// "at most one live session per (user, device, IP)" invariant.
///
/// The purge + INSERT pair runs inside a single transaction so an
/// inter-request race within the same pod cannot create two rows. If
/// another pod (multi-replica deployment) wins the race between the
/// purge and the INSERT, the UNIQUE index trips a `UniqueViolation`;
/// we retry once after re-purging, which converges because the second
/// purge picks up the row inserted by the other pod.
async fn insert_session_with_purge(
    conn: &mut diesel_async::AsyncPgConnection,
    user_id_val: i32,
    device_info_str: String,
    client_ip: ipnetwork::IpNetwork,
    new_session: NewAuthSession,
) -> Result<(), diesel::result::Error> {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};
    use diesel_async::AsyncConnection;

    for attempt in 0u8..2 {
        let device_info_attempt = device_info_str.clone();
        let new_session_attempt = new_session.clone();
        let result = conn
            .transaction::<_, DieselError, _>(|conn| {
                Box::pin(async move {
                    // Clear `is_current` on other sessions for this user
                    // (the same-device row will be deleted by the purge
                    // below; this only affects sessions on other devices).
                    diesel::update(
                        auth_sessions::table
                            .filter(auth_sessions::user_id.eq(user_id_val))
                            .filter(auth_sessions::is_current.eq(true)),
                    )
                    .set(auth_sessions::is_current.eq(false))
                    .execute(conn)
                    .await?;

                    purge_sessions_for_device(conn, user_id_val, &device_info_attempt, client_ip)
                        .await?;

                    diesel::insert_into(auth_sessions::table)
                        .values(&new_session_attempt)
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .await;

        match result {
            Ok(()) => return Ok(()),
            Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _))
                if attempt == 0 =>
            {
                tracing::warn!(
                    user_id = user_id_val,
                    "Unique violation on auth_sessions INSERT; retrying once after re-purge"
                );
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    // Unreachable: the loop either returns Ok, returns Err, or continues
    // exactly once before exiting on the second attempt.
    unreachable!("insert_session_with_purge retry loop exited without returning")
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

use crate::middleware::extract_client_ip;

/// Logout handler.
/// Invalidates the current session in the database and clears the cookie.
pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> Response {
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
                crate::handlers::web::broadcast_admin_sessions_update(&state).await;
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
    browser_tz: BrowserTz,
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
    // When vault is available, secrets are encrypted at rest.
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
                let encrypted = vault
                    .encrypt("mfa", &s)
                    .await
                    .map_err(|e| AppError::Internal(anyhow::anyhow!("MFA encryption: {}", e)))?;
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
            let qr =
                AuthService::generate_totp_qr_code(plaintext.as_str(), &user_username, "VAUBAN")?;
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
    let base = BaseTemplate::new("MFA Setup".to_string(), None, browser_tz.0)
        .with_messages(flash_messages);
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
    // Verify via vault when available (encrypted secrets), or directly (plaintext, pre-migration)
    let code = form.totp_code.trim();
    // Issue #11 hardening: if the stored secret is encrypted but the vault
    // client is unavailable, refuse with an explicit "backend unavailable"
    // message instead of silently calling `verify_totp` on the ciphertext
    // (which would always return false and tell the operator their CORRECT
    // code is wrong, looping them forever).
    if is_encrypted(&secret) && state.vault_client.is_none() {
        tracing::error!(
            user_id,
            "mfa setup verify: secret is encrypted but vault client is not configured"
        );
        return Ok(flash_redirect(
            flash.error(
                "MFA backend is temporarily unavailable. Please try again \
                 in a moment, or contact an administrator if the problem persists.",
            ),
            "/mfa/setup",
        ));
    }
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

    let session_uuid = resolve_auth_session_uuid(&mut conn, &claims, &token)
        .await
        .map_err(AppError::Database)?;

    // Generate new JWT with mfa_verified = true
    let new_token = state.auth_service.generate_access_token(
        &claims.sub,
        &user_username,
        true, // mfa_verified
        is_super,
        is_staff_user,
        session_uuid,
    )?;

    // Update the session in database with new token hash
    let new_token_hash = hash_token(&new_token);
    if let Some(sid) = session_uuid {
        diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(sid)))
            .set(auth_sessions::token_hash.eq(new_token_hash))
            .execute(&mut conn)
            .await
            .ok();
    } else {
        let old_token_hash = hash_token(&token);
        diesel::update(auth_sessions::table.filter(auth_sessions::token_hash.eq(&old_token_hash)))
            .set(auth_sessions::token_hash.eq(new_token_hash))
            .execute(&mut conn)
            .await
            .ok();
    }

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
    browser_tz: BrowserTz,
) -> AppResult<Response> {
    // Verify user is authenticated (via cookie)
    let token = jar
        .get("access_token")
        .map(|c| c.value().to_string())
        .ok_or_else(|| AppError::Auth("Not authenticated".to_string()))?;

    let claims = state.auth_service.verify_token(&token)?;

    // If the user hasn't set up MFA yet, redirect to /mfa/setup
    let user_uuid_parsed = ::uuid::Uuid::parse_str(&claims.sub)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid UUID in token: {}", e)))?;
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB pool error: {}", e)))?;
    let user_mfa_enabled: bool = crate::schema::users::table
        .filter(crate::schema::users::uuid.eq(user_uuid_parsed))
        .select(crate::schema::users::mfa_enabled)
        .first::<bool>(&mut conn)
        .await
        .map_err(|_| AppError::Auth("User not found".to_string()))?;

    if !user_mfa_enabled {
        return Ok(Redirect::to("/mfa/setup").into_response());
    }

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
    let base = BaseTemplate::new("Verify Identity".to_string(), None, browser_tz.0)
        .with_messages(flash_messages);
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
    // Verify via vault when available (encrypted secrets), or directly (plaintext, pre-migration)
    let code = form.totp_code.trim();
    // Issue #11 hardening: same "encrypted secret + no vault" guard as in
    // the MFA setup flow above. Without this, an operator whose secret was
    // enrolled through the vault but whose web process lost the vault IPC
    // would be told indefinitely that their valid code is invalid.
    if is_encrypted(&secret) && state.vault_client.is_none() {
        tracing::error!(
            user_id,
            "mfa verify: secret is encrypted but vault client is not configured"
        );
        return Ok(flash_redirect(
            flash.error(
                "MFA backend is temporarily unavailable. Please try again \
                 in a moment, or contact an administrator if the problem persists.",
            ),
            "/mfa/verify",
        ));
    }
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

    let session_uuid = resolve_auth_session_uuid(&mut conn, &claims, &token)
        .await
        .map_err(AppError::Database)?;

    // Generate new JWT with mfa_verified = true
    let new_token = state.auth_service.generate_access_token(
        &claims.sub,
        &user_username,
        true, // mfa_verified
        is_super,
        is_staff_user,
        session_uuid,
    )?;

    // Update the session in database with new token hash
    let new_token_hash = hash_token(&new_token);
    if let Some(sid) = session_uuid {
        diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(sid)))
            .set(auth_sessions::token_hash.eq(new_token_hash))
            .execute(&mut conn)
            .await
            .ok();
    } else {
        let old_token_hash = hash_token(&token);
        diesel::update(auth_sessions::table.filter(auth_sessions::token_hash.eq(&old_token_hash)))
            .set(auth_sessions::token_hash.eq(new_token_hash))
            .execute(&mut conn)
            .await
            .ok();
    }

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
    use std::net::SocketAddr;

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
            auth_source: AuthSource::Local,
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
            auth_source: AuthSource::Local,
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
        headers.insert("X-Forwarded-For", unwrap_ok!("203.0.113.50".parse()));

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

        // html_error_fragment translates "Invalid credentials" to "Incorrect username or password"
        assert!(html.contains("Incorrect username or password"));
        assert!(html.contains("login-result"));
        assert!(html.contains("bg-red-50"));
    }

    #[test]
    fn test_login_error_html_no_account_state_leakage() {
        let html = login_error_html(LoginErrorKind::InvalidCredentials);
        assert!(!html.contains("locked"));
        assert!(!html.contains("deactivated"));
        assert!(html.contains("login-result"));
    }

    #[test]
    fn test_login_error_html_csrf_message() {
        let html = login_error_html(LoginErrorKind::InvalidCsrf);
        assert!(html.contains("Invalid or expired form"));
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
        // Password and mfa_code MUST be redacted
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
            auth_source: AuthSource::Local,
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

    // ==================== API Login MFA Enforcement Tests (Finding #2) ==========
    //
    // These structural tests guard the fix for the historical "API users
    // can bypass MFA setup" finding. The bug was a single `else` branch
    // that silently set `mfa_verified = true` when `user.mfa_enabled` was
    // false. The tests below scan the production source so a regression
    // (e.g. someone re-introducing the M2M shortcut) is caught at
    // compile/test time.

    /// Helper: extract the body of `pub async fn login(` (the API login
    /// handler) from the production source, stopping at the next public
    /// item or the test module.
    fn login_handler_source() -> &'static str {
        let full = include_str!("auth.rs");
        // Strip the test module specifically -- there are other `#[cfg(test)]`
        // attributes earlier in the file (on imports), so we can't naively
        // split on the first `#[cfg(test)]`.
        let prod = full
            .find("#[cfg(test)]\nmod tests")
            .map(|i| &full[..i])
            .unwrap_or(full);
        // Disambiguate from `login_web`: we want the bare `pub async fn login(`.
        let needle = "pub async fn login(";
        let start = prod.find(needle).expect("login API handler must exist");
        let after = &prod[start..];
        // Stop at the next `pub async fn ` (login_web, logout, etc.).
        let end = after[needle.len()..]
            .find("pub async fn ")
            .map(|o| needle.len() + o)
            .unwrap_or(after.len());
        &after[..end]
    }

    /// The historical bypass shipped these literal comments. Their
    /// presence is the smoking gun for a regression.
    #[test]
    fn test_api_login_does_not_carry_legacy_bypass_comments() {
        let body = login_handler_source();
        for needle in [
            "API users don't need to set up MFA",
            "API login proceeds without MFA",
            "temporary inconsistency",
            "legacy behavior for M2M compatibility",
        ] {
            assert!(
                !body.contains(needle),
                "API login handler still carries the legacy bypass comment: {:?}. \
                 The bypass branch must be removed; reject API login when \
                 mfa_enabled is false.",
                needle
            );
        }
    }

    /// The bypass shape was:
    ///     } else {
    ///         // ...
    ///         true
    ///     };
    /// after a `if user.mfa_enabled { ... }`. We now require an explicit
    /// fail-closed return on the !mfa_enabled path.
    #[test]
    fn test_api_login_rejects_account_without_mfa() {
        let body = login_handler_source();
        // The new code must contain the explicit early-return for accounts
        // without MFA. We assert on a stable substring of the new error.
        assert!(
            body.contains("MFA setup is required before API login"),
            "API login handler must explicitly reject accounts that have \
             not completed MFA setup with a clear error message"
        );
        // Defence in depth: the new code must check `!user.mfa_enabled`
        // and call `AppError::Authorization`.
        assert!(
            body.contains("!user.mfa_enabled"),
            "API login handler must branch on `!user.mfa_enabled` to fail closed"
        );
        assert!(
            body.contains("AppError::Authorization"),
            "API login handler must return AppError::Authorization (403) \
             for accounts without MFA, not silently mint a trusted token"
        );
    }

    /// The strongest invariant: there must be **no** literal `true` value
    /// being assigned to a variable named `mfa_verified` anywhere in the
    /// API login handler. The only valid sources of `mfa_verified = true`
    /// are (a) successful TOTP verification (computed at runtime) and
    /// (b) the post-MFA step-up handlers (which live in a different
    /// function and are explicitly tested).
    #[test]
    fn test_api_login_never_hardcodes_mfa_verified_true() {
        let body = login_handler_source();
        // Forbid the exact literal that was the bypass.
        assert!(
            !body.contains("mfa_verified = true"),
            "API login handler must not hardcode `mfa_verified = true`. \
             Only successful TOTP verification may set it."
        );
        // Also forbid the historical short form `_ => true,` style on this
        // path: the bypass `else { true }` shape.
        let normalized: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            !normalized.contains("} else { true }"),
            "API login handler must not contain `}} else {{ true }}` on the \
             MFA path -- this was the historical bypass shape."
        );
    }
}
