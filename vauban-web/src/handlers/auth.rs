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
use diesel::OptionalExtension;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use askama::Template;

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::ipc::AuditEvent;
use crate::middleware::browser_tz::BrowserTz;
use crate::middleware::flash::{IncomingFlash, flash_redirect};
use crate::models::auth_session::{AuthSession, NewAuthSession};
use crate::models::user::{AuthSource, NewUser, User};
use crate::schema::{auth_sessions, users::dsl::*};
use crate::services::auth::{AuthService, Claims, is_encrypted_mfa_secret};
use crate::services::{emit_audit, emit_audit_critical};
use crate::templates::accounts::{MfaSetupTemplate, MfaVerifyTemplate};
use crate::templates::base::BaseTemplate;
use shared::messages::AuditEventType;

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
///
/// Credential length floors are enforced at runtime against
/// `[auth.ldaps].login_*_min_length` (absolute floors 3 / 12), not via
/// compile-time `validator` attributes.
#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub mfa_code: Option<String>,
    pub csrf_token: Option<String>,
}

/// Canonical warn message when login credentials are shorter than the
/// configured `[auth.ldaps]` floors (LDAPS bind is not attempted).
pub const LOGIN_CREDS_BELOW_MINS_WARN: &str =
    "login credentials below configured minimums; LDAPS bind not attempted";

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
    let rate_key = format!("login:{}", client_addr.ip());
    let rate_result = state
        .rate_limiter
        .check(&rate_key, state.config.security.rate_limit_per_minute)
        .await?;
    if !rate_result.allowed {
        return rate_limit_response(htmx, rate_result.reset_in_secs);
    }

    // Login-form length floors (`[auth.ldaps].login_*_min_length`, absolute
    // mins 3 / 12). Return the same generic error as invalid credentials to
    // prevent policy enumeration (SEC-05). When rejected, warn so operators
    // can see that LDAPS was never contacted for this reason.
    let user_min = state.config.auth.ldaps.login_username_min_length;
    let pass_min = state.config.auth.ldaps.login_password_min_length;
    let username_len = request.username.chars().count();
    let password_len = request.password.chars().count();
    if !shared::validation::credentials_meet_login_mins(
        &request.username,
        &request.password,
        user_min,
        pass_min,
    ) {
        // tracing macros require a string literal for the message body; the
        // structured `reason` field carries [`LOGIN_CREDS_BELOW_MINS_WARN`] so
        // the const cannot drift unused, and the unit pin keeps both equal.
        tracing::warn!(
            username_len,
            password_len,
            login_username_min_length = user_min,
            login_password_min_length = pass_min,
            ldap_enabled = state.config.auth.ldaps.enabled,
            reason = LOGIN_CREDS_BELOW_MINS_WARN,
            "login credentials below configured minimums; LDAPS bind not attempted"
        );
        return login_error_response(htmx, LoginErrorKind::InvalidCredentials);
    }

    // Bind-DN allowlist (same charset as local account creation). Applied
    // to the trimmed identifier before any directory IPC so a crafted
    // value cannot steer the LDAPS simple bind. Surrounding whitespace is
    // form noise (`normalize_username` already strips it for lookup) and
    // must not reject a padded local login; the trimmed value (case
    // preserved for AD) is what we hand to the bind so spaces never enter
    // the DN. Generic InvalidCredentials: no policy oracle.
    let bind_username = request.username.trim();
    if !shared::ldap_dn::username_allowed_in_bind_dn(bind_username) {
        tracing::warn!(
            ldap_enabled = state.config.auth.ldaps.enabled,
            "login username rejected by bind-DN allowlist; LDAPS bind not attempted"
        );
        return login_error_response(htmx, LoginErrorKind::InvalidCredentials);
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Database connection error: {}", e)))?;

    // Find user by username. Logins are case-insensitive: the stored
    // identity column is canonicalised to its `normalize_username` form
    // (trimmed + lower-cased) at every write site, so we look it up by
    // the same canonical form. The trimmed `bind_username` (case
    // preserved) is what gets handed to the directory bind below (an
    // LDAP/AD bind DN may use a case-exact attribute; AD is
    // case-insensitive anyway).
    let lookup_username = shared::username::normalize_username(&request.username);
    let existing_user = users
        .filter(username.eq(&lookup_username))
        .filter(is_deleted.eq(false))
        .first::<User>(&mut conn)
        .await
        .optional()
        .map_err(AppError::Database)?;

    // SEC-04: credentials are verified BEFORE any account-state / existence
    // check so an attacker with an invalid password only ever sees the generic
    // "Invalid credentials" response. The routing below is by `auth_source`:
    //
    //  * existing `Ldap` user  -> LDAP bind only, NEVER a local fallback
    //    (anti-downgrade) and NEVER touching the local lockout counters (the
    //    directory owns its own lockout).
    //  * existing `Local` user -> the historical Argon2 path, including the
    //    progressive local lockout.
    //  * unknown username       -> optional LDAP just-in-time provisioning when
    //    `[auth.ldaps]` is enabled and lists "ldap"; otherwise generic failure.
    //
    // Every LDAP failure mode (bad password, directory down, TLS error) is
    // collapsed to the same generic response (anti-enumeration, SEC-04/05).
    let user = match existing_user {
        Some(u) if u.auth_source == AuthSource::Ldap => {
            if !ldap_bind_succeeds(&state, bind_username, &request.password).await {
                emit_audit(
                    &state,
                    AuditEvent::new(
                        AuditEventType::AuthFailure,
                        r#"{"reason":"ldap_bind_failed","auth_source":"ldap"}"#,
                    )
                    .user(&request.username)
                    .ip(Some(client_addr.ip())),
                );
                return login_error_response(htmx, LoginErrorKind::InvalidCredentials);
            }
            u
        }
        Some(u) => {
            let password_valid = if let Some(ref client) = state.auth_ipc_client {
                client
                    .verify_password(&request.password, &u.password_hash)
                    .await?
            } else {
                state
                    .auth_service
                    .verify_password(&request.password, &u.password_hash)?
            };
            if !password_valid {
                let new_failed_attempts = u.failed_login_attempts + 1;
                let locked_until_value = lockout_duration_for_attempts(
                    new_failed_attempts,
                    state.config.security.max_failed_login_attempts,
                )
                .map(|duration| Utc::now() + duration);

                diesel::update(users.find(u.id))
                    .set((
                        failed_login_attempts.eq(new_failed_attempts),
                        locked_until.eq(locked_until_value),
                    ))
                    .execute(&mut conn)
                    .await
                    .map_err(AppError::Database)?;

                // SEC-04: always return generic "Invalid credentials" regardless
                // of whether lockout was triggered, to prevent enumeration.
                // Audit: fire-and-forget (never block the login response; a
                // brute-force flood must not be a DoS vector on the request path).
                emit_audit(
                    &state,
                    AuditEvent::new(
                        AuditEventType::AuthFailure,
                        r#"{"reason":"invalid_password","auth_source":"local"}"#,
                    )
                    .user(&request.username)
                    .ip(Some(client_addr.ip())),
                );
                return login_error_response(htmx, LoginErrorKind::InvalidCredentials);
            }
            u
        }
        None => {
            // Unknown username: try LDAP JIT provisioning if configured. The
            // bind happens against the username supplied; on success we create
            // a directory-backed local shadow account and proceed to MFA.
            if state.config.auth.ldaps.jit_enabled()
                && ldap_bind_succeeds(&state, bind_username, &request.password).await
            {
                jit_provision_ldap_user(&mut conn, bind_username).await?
            } else {
                // Anti-enumeration: pay the same Argon2 cost as a real
                // wrong-password failure so response timing cannot reveal
                // whether the username exists (SEC-04/05 timing oracle).
                crate::services::auth::equalize_login_timing(&state).await;
                emit_audit(
                    &state,
                    AuditEvent::new(AuditEventType::AuthFailure, r#"{"reason":"unknown_user"}"#)
                        .user(&request.username)
                        .ip(Some(client_addr.ip())),
                );
                return login_error_response(htmx, LoginErrorKind::InvalidCredentials);
            }
        }
    };

    // SEC-04: account state checks after credential verification -- an attacker
    // with an invalid password only ever sees "Invalid credentials".
    if user.is_locked() || !user.is_active {
        emit_audit(
            &state,
            AuditEvent::new(
                AuditEventType::AuthFailure,
                r#"{"reason":"account_locked_or_inactive"}"#,
            )
            .user(&user.username)
            .ip(Some(client_addr.ip())),
        );
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

        // Audit: credentials accepted (web flow, MFA still pending). Fire-and-
        // forget: the privileged elevation is recorded at MFA verification.
        emit_audit(
            &state,
            AuditEvent::new(
                AuditEventType::AuthSuccess,
                r#"{"flow":"web","mfa":"pending"}"#,
            )
            .user(&user.username)
            .ip(Some(client_addr.ip())),
        );

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

    // Audit: a full API login (credentials + MFA) is a privileged, low-volume
    // escalation -> fail-closed (durable ack required before we hand out the
    // trusted session token).
    emit_audit_critical(
        &state,
        AuditEvent::new(
            AuditEventType::AuthSuccess,
            r#"{"flow":"api","mfa":"verified"}"#,
        )
        .user(&user.username)
        .ip(Some(client_addr.ip())),
    )
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("audit emit failed: {e}")))?;

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
        // Self-heal: a stale or desynchronized double-submit pair (typical
        // after a session-expiry redirect to `/login?reason=...`) would
        // otherwise loop forever, because `csrf_cookie_middleware` re-mints
        // the cookie on the error response WITHOUT updating the form's hidden
        // field. We mint a fresh token here and ship BOTH the new cookie and
        // an OOB swap of the hidden input, so the very next submit succeeds
        // without a manual page reload. The user-facing message is unchanged
        // (SEC-04).
        return login_csrf_error_response(htmx, jar, secret);
    }
    login(State(state), client_addr, headers, jar, Json(request)).await
}

/// Password-hash sentinel stored for directory-backed accounts. It is a
/// syntactically invalid Argon2 encoding, so the local verification path can
/// never accept it -- LDAP users authenticate exclusively through the bind.
const LDAP_PASSWORD_SENTINEL: &str = "!ldap-no-local-login";

/// Forward an LDAP simple bind to vauban-auth and reduce the coarse outcome to
/// a boolean. Returns `false` (fail-closed) when LDAP is disabled or the auth
/// IPC client is unavailable. The distinct non-success outcomes are logged
/// internally but NEVER surfaced to the caller (anti-enumeration, SEC-04/05).
async fn ldap_bind_succeeds(state: &AppState, login_name: &str, password: &str) -> bool {
    if !state.config.auth.ldaps.enabled {
        return false;
    }
    let Some(ref client) = state.auth_ipc_client else {
        tracing::error!("LDAP login attempted but auth IPC client is not configured");
        return false;
    };
    match client.ldap_bind(login_name, password).await {
        Ok(shared::messages::LdapBindOutcome::Success) => true,
        Ok(outcome) => {
            tracing::info!(?outcome, login_name, "LDAP bind rejected");
            false
        }
        Err(e) => {
            tracing::warn!(error = %e, login_name, "LDAP bind IPC error");
            false
        }
    }
}

/// Just-in-time provision a directory-backed account after a successful LDAP
/// bind for a username Vauban had never seen. The shadow row carries
/// `auth_source = Ldap`, the username as `external_id`, a sentinel password
/// hash, and `is_active = true`. MFA is NOT pre-enabled, so the caller routes
/// the user through `/mfa/setup` exactly like any other first login.
async fn jit_provision_ldap_user(
    conn: &mut diesel_async::AsyncPgConnection,
    login_name: &str,
) -> AppResult<User> {
    // No LDAP search is performed in v1, so we have no authoritative e-mail.
    // Derive a deterministic, non-routable placeholder (or reuse the value
    // when the username already looks like a UPN) to satisfy the NOT NULL
    // e-mail column (duplicates are allowed since
    // 20260704000000_users_email_drop_unique). Operators can edit it
    // afterwards.
    let email_value = if login_name.contains('@') {
        login_name.to_lowercase()
    } else {
        format!("{}@ldap.local", login_name.to_lowercase())
    };

    let new_user = NewUser {
        uuid: ::uuid::Uuid::new_v4(),
        // Canonical (case-insensitive) identity. The original casing the
        // directory user typed is preserved verbatim in `external_id`
        // below so the audit trail keeps the as-seen value.
        username: shared::username::normalize_username(login_name),
        email: email_value,
        password_hash: LDAP_PASSWORD_SENTINEL.to_string(),
        first_name: None,
        last_name: None,
        phone: None,
        is_active: true,
        is_staff: false,
        is_superuser: false,
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: AuthSource::Ldap,
        external_id: Some(login_name.to_string()),
    };

    let user = diesel::insert_into(crate::schema::users::table)
        .values(&new_user)
        .returning(User::as_returning())
        .get_result::<User>(conn)
        .await
        .map_err(AppError::Database)?;

    tracing::info!(
        user_id = user.id,
        username = %user.username,
        "JIT-provisioned directory user on first LDAP login"
    );
    Ok(user)
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

/// The exact generic "Invalid credentials" login failure, exposed for the
/// IP-ACL middleware short-circuit ([`crate::middleware::ip_acl`]). A login
/// attempt from a denied client IP MUST be byte-for-byte identical to a
/// wrong-password failure (stealth deny, SEC-04/05), so the middleware
/// reuses this response instead of crafting its own.
pub(crate) fn login_invalid_credentials_response(htmx: bool) -> AppResult<Response> {
    login_error_response(htmx, LoginErrorKind::InvalidCredentials)
}

/// HTMX error fragment for a CSRF failure, augmented with an out-of-band swap
/// that refreshes the form's hidden `csrf_token` field with `new_token`.
///
/// The leading `#login-result` div keeps the existing red banner (SEC-04
/// wording unchanged); the trailing `<input>` carries `hx-swap-oob` so HTMX
/// replaces the stale hidden field in place. `new_token` is server-minted
/// (base64 + signature), so it never contains HTML-significant characters.
fn login_csrf_error_html(new_token: &str) -> String {
    format!(
        r#"{}<input type="hidden" name="csrf_token" id="login-csrf-token" value="{}" hx-swap-oob="outerHTML" />"#,
        login_error_html(LoginErrorKind::InvalidCsrf),
        new_token
    )
}

/// CSRF-failure response for the web login form.
///
/// HTMX path: mints a fresh CSRF token, sets the cookie AND returns the OOB
/// hidden-field swap so cookie and form stay synchronized and the next submit
/// succeeds without a manual reload. The handler-set cookie suppresses the
/// middleware's own re-mint (`csrf_cookie_middleware` checks
/// `handler_set_cookie`).
///
/// Non-HTMX path: unchanged `AppError::Auth` (JSON/API surface).
fn login_csrf_error_response(htmx: bool, jar: CookieJar, secret: &[u8]) -> AppResult<Response> {
    if htmx {
        use crate::middleware::csrf::{build_csrf_cookie, generate_csrf_token};
        let new_token = generate_csrf_token(secret);
        let cookie = build_csrf_cookie(&new_token);
        let body = login_csrf_error_html(&new_token);
        Ok((jar.add(cookie), Html(body)).into_response())
    } else {
        Err(AppError::Auth(
            LoginErrorKind::InvalidCsrf.message().to_string(),
        ))
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
                emit_audit(
                    &state,
                    AuditEvent::new(AuditEventType::Logout, "{}").user(user_uuid_val.to_string()),
                );
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

/// Form for the MFA setup initialization (POST /mfa/setup/init).
///
/// VAU-008 (ephemeral): the `password` field is GONE. First enrolment needs
/// only a valid CSRF token (the user just logged in). For ROTATION (already
/// enrolled) the caller must prove the current factor with a valid
/// `totp_code`; it is `Option` because first enrolment omits it.
#[derive(Deserialize, Debug)]
pub struct MfaInitForm {
    pub csrf_token: String,
    #[serde(default)]
    pub totp_code: Option<String>,
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

    // VAU-008 (ephemeral): this GET is strictly READ-ONLY. The candidate TOTP
    // secret is created exclusively by `POST /mfa/setup/init` (CSRF gated) and
    // lives ONLY in the per-session in-memory store, never in `users`. Here we
    // render one of three states without ever producing or persisting a secret
    // (no DB write, no generation), which is what closes the GET-side-effect /
    // CSRF vector:
    //   (a) a candidate is in flight for THIS session -> QR + confirm form;
    //   (b) not enrolled, no candidate -> "Configure 2FA" button (no password);
    //   (c) already enrolled, no candidate -> current-TOTP step-up (rotation).
    let (user_username, mfa_already_enabled): (String, bool) = users
        .filter(uuid.eq(user_uuid))
        .filter(is_deleted.eq(false))
        .select((
            crate::schema::users::username,
            crate::schema::users::mfa_enabled,
        ))
        .first(&mut conn)
        .await
        .map_err(AppError::Database)?;

    // The per-session candidate is keyed by the JWT `jti` (= auth_sessions.uuid
    // on the pre-MFA token). A web flow always carries one; its absence means a
    // malformed/non-web token, so steer back to login rather than leaking a
    // shared candidate.
    let Some(ref session_jti) = claims.jti else {
        return Ok(Redirect::to("/login").into_response());
    };

    let candidate = state.pending_mfa.get(&claims.sub, session_jti);

    let (show_qr, needs_totp_stepup, secret, mut qr_code_base64) = match candidate {
        Some(ref s) => {
            let (plaintext_secret, qr) = mfa_qr_from_secret(&state, s, &user_username).await?;
            (true, false, plaintext_secret, qr)
        }
        // No candidate: rotation (enrolled) needs a current-TOTP step-up;
        // first enrolment just needs the CSRF-protected button.
        None => (false, mfa_already_enabled, String::new(), String::new()),
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
        show_qr,
        needs_totp_stepup,
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

/// VAU-008: derive the manual-entry (Base32) secret and a base64 PNG QR code
/// from a stored candidate/secret value, decrypting via the vault when the
/// value is an encrypted envelope. Pure: performs no DB write. Returns
/// `(plaintext_base32_secret, qr_code_base64)`.
pub(crate) async fn mfa_qr_from_secret(
    state: &AppState,
    stored_secret: &str,
    account_username: &str,
) -> AppResult<(String, String)> {
    if let Some(ref vault) = state.vault_client
        && is_encrypted(stored_secret)
    {
        let plaintext = vault
            .mfa_get_secret(stored_secret)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("MFA secret decryption: {}", e)))?;
        let qr =
            AuthService::generate_totp_qr_code(plaintext.as_str(), account_username, "VAUBAN")?;
        return Ok((plaintext.as_str().to_string(), qr));
    }
    // Plaintext secret (dev mode without vault, or a not-yet-encrypted value):
    // generate the QR directly from the stored Base32 secret.
    let qr = AuthService::generate_totp_qr_code(stored_secret, account_username, "VAUBAN")?;
    Ok((stored_secret.to_string(), qr))
}

/// MFA setup initialization handler (POST /mfa/setup/init).
///
/// VAU-008 (ephemeral): the ONLY place a TOTP secret is (re)generated. Gated by
/// CSRF. The generated candidate is written ONLY to the per-session in-memory
/// store ([`AppState::pending_mfa`]), NEVER to `users` -- so a GET can never
/// enrol a factor and two sessions of the same account get distinct secrets.
///
/// Step-up policy:
///   * FIRST enrolment (`mfa_enabled == false`): no step-up. The user just
///     authenticated with their password at login; a second password prompt
///     was redundant and hostile to UX.
///   * ROTATION (`mfa_enabled == true`): proof of the CURRENT factor is
///     required (a valid `totp_code` verified against the active `mfa_secret`).
///
/// On success it stores the candidate, emits `MfaSecretGenerated`, then
/// redirects back to `GET /mfa/setup` (Post/Redirect/Get). On any failure
/// (CSRF, missing session, wrong current code) no candidate is created.
pub async fn mfa_setup_init(
    State(state): State<AppState>,
    jar: CookieJar,
    incoming_flash: IncomingFlash,
    Form(form): Form<MfaInitForm>,
) -> AppResult<Response> {
    let flash = incoming_flash.flash();

    // Validate CSRF (double-submit), exactly like the confirm POST.
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

    // Authenticated via the (pre-MFA) session cookie.
    let token = jar
        .get("access_token")
        .map(|c| c.value().to_string())
        .ok_or_else(|| AppError::Auth("Not authenticated".to_string()))?;
    let claims = state.auth_service.verify_token(&token)?;

    // The candidate is keyed by the login session (JWT `jti`). Without one we
    // cannot isolate it per session, so refuse rather than fall back to a
    // shared candidate.
    let Some(session_jti) = claims.jti.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Database connection error: {}", e)))?;
    use ::uuid::Uuid as UuidType;
    let user_uuid = UuidType::parse_str(&claims.sub)
        .map_err(|_| AppError::Validation("Invalid user UUID".to_string()))?;

    let (user_id, user_username, mfa_already_enabled, current_secret): (
        i32,
        String,
        bool,
        Option<String>,
    ) = users
        .filter(uuid.eq(user_uuid))
        .filter(is_deleted.eq(false))
        .select((
            crate::schema::users::id,
            crate::schema::users::username,
            crate::schema::users::mfa_enabled,
            crate::schema::users::mfa_secret,
        ))
        .first(&mut conn)
        .await
        .map_err(AppError::Database)?;

    // ROTATION step-up: prove the CURRENT factor. On failure: NO candidate
    // generated. The message is deliberately generic so it is not an oracle.
    if mfa_already_enabled {
        let code = form.totp_code.as_deref().unwrap_or("").trim().to_string();
        let Some(ref active_secret) = current_secret else {
            tracing::error!(user_id, "mfa rotation: mfa_enabled but mfa_secret is NULL");
            return Ok(flash_redirect(
                flash.error("Two-factor is in an inconsistent state. Contact an administrator."),
                "/mfa/setup",
            ));
        };
        // Refuse explicitly when the secret is an encrypted envelope but the
        // vault IPC is unavailable (issue #11 hardening): never call
        // `verify_totp` on ciphertext (would loop a correct code as invalid).
        if is_encrypted(active_secret) && state.vault_client.is_none() {
            tracing::error!(
                user_id,
                "mfa rotation: active secret is encrypted but vault client is not configured"
            );
            return Ok(flash_redirect(
                flash.error(
                    "MFA backend is temporarily unavailable. Please try again \
                     in a moment, or contact an administrator if the problem persists.",
                ),
                "/mfa/setup",
            ));
        }
        let current_ok = if let Some(ref vault) = state.vault_client
            && is_encrypted(active_secret)
        {
            vault
                .mfa_verify(active_secret, &code)
                .await
                .unwrap_or(false)
        } else {
            AuthService::verify_totp(active_secret, &code)
        };
        if !current_ok {
            tracing::warn!(user_id, "mfa rotation: current-code step-up failed");
            return Ok(flash_redirect(
                flash.error("Invalid verification code. Please try again."),
                "/mfa/setup",
            ));
        }
    }

    // Generate a fresh candidate secret. Encrypted at rest when a vault is
    // configured; plaintext Base32 in dev. Stored ONLY in the per-session
    // in-memory store -- never in `users` -- so it is never persisted before
    // confirmation and never shared across sessions. A previous candidate for
    // this session is overwritten (regenerate as many times as necessary).
    let candidate = if let Some(ref vault) = state.vault_client {
        let (encrypted_secret, _plaintext) = vault
            .mfa_generate(&user_username, "VAUBAN")
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("MFA generation: {}", e)))?;
        encrypted_secret
    } else {
        let (new_secret, _uri) = AuthService::generate_totp_secret(&user_username, "VAUBAN")?;
        new_secret
    };

    state.pending_mfa.put(&claims.sub, &session_jti, candidate);

    // Audit (INV-4): a (re)generation of a second-factor secret is
    // security-relevant. Fire-and-forget so a missing audit sink cannot wedge
    // the setup flow; the durable ack is reserved for the enrolment itself.
    emit_audit(
        &state,
        AuditEvent::new(AuditEventType::MfaSecretGenerated, "{}").user(&claims.sub),
    );

    Ok(flash_redirect(
        flash
            .success("Scan the QR code with your authenticator app, then enter a code to confirm."),
        "/mfa/setup",
    ))
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

    // VAU-008 (ephemeral): confirmation reads the CANDIDATE secret from the
    // per-session in-memory store, never from `users`. The candidate is created
    // only by POST /mfa/setup/init (CSRF gated). Promotion to `users.mfa_secret`
    // happens here, and only here, after a valid TOTP code -- so a GET can never
    // enrol a factor and a generation never overwrites an already-enrolled
    // secret.
    let (user_id, user_username, is_super, is_staff_user): (i32, String, bool, bool) = users
        .filter(uuid.eq(user_uuid))
        .filter(is_deleted.eq(false))
        .select((
            crate::schema::users::id,
            crate::schema::users::username,
            crate::schema::users::is_superuser,
            crate::schema::users::is_staff,
        ))
        .first(&mut conn)
        .await
        .map_err(AppError::Database)?;

    // The candidate is bound to THIS login session (JWT `jti`).
    let Some(session_jti) = claims.jti.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };

    // Fetch the candidate. `get` enforces the TTL: an absent or stale entry
    // (older than `PendingMfaStore::TTL`) returns `None` and is evicted, so a
    // forgotten setup cannot be confirmed much later. In both "never started"
    // and "expired" cases we steer the user back to the GET (which renders the
    // start/step-up form) instead of erroring on a missing secret.
    let Some(secret) = state.pending_mfa.get(&claims.sub, &session_jti) else {
        return Ok(flash_redirect(
            flash.error("Two-factor setup expired or not started. Please start again."),
            "/mfa/setup",
        ));
    };

    // Validate TOTP code against the CANDIDATE secret.
    // Verify via vault when available (encrypted secrets), or directly (dev).
    let code = form.totp_code.trim();
    // Issue #11 hardening: if the candidate secret is encrypted but the vault
    // client is unavailable, refuse with an explicit "backend unavailable"
    // message instead of silently calling `verify_totp` on the ciphertext
    // (which would always return false and tell the operator their CORRECT
    // code is wrong, looping them forever).
    if is_encrypted(&secret) && state.vault_client.is_none() {
        tracing::error!(
            user_id,
            "mfa setup verify: candidate secret is encrypted but vault client is not configured"
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

    // Promote the candidate to the active secret and enable MFA in a single
    // update. `mfa_secret` is mutated ONLY here (INV-1/INV-3). The candidate is
    // already encrypted at rest when a vault is configured (it was produced by
    // `vault.mfa_generate` in the init step).
    diesel::update(users.filter(crate::schema::users::id.eq(user_id)))
        .set((
            crate::schema::users::mfa_secret.eq(Some(&secret)),
            crate::schema::users::mfa_enabled.eq(true),
            crate::schema::users::updated_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .map_err(AppError::Database)?;

    // Candidate consumed: drop it from the in-memory store so it cannot be
    // re-confirmed and to bound memory.
    state.pending_mfa.evict(&claims.sub, &session_jti);

    // Audit: MFA enrolment is a security-relevant credential change.
    emit_audit_critical(
        &state,
        AuditEvent::new(AuditEventType::MfaEnrolled, "{}").user(&claims.sub),
    )
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("audit emit failed: {e}")))?;

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
        emit_audit(
            &state,
            AuditEvent::new(AuditEventType::MfaChallengeFailed, "{}").user(&claims.sub),
        );
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

    // Audit: TOTP challenge passed -> the session is about to be elevated to a
    // fully-trusted (mfa_verified) token. This is the privileged escalation
    // moment, so fail-closed (durable ack required before we mint the token).
    emit_audit_critical(
        &state,
        AuditEvent::new(AuditEventType::MfaChallengePassed, "{}").user(&claims.sub),
    )
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("audit emit failed: {e}")))?;

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

        assert!(shared::validation::credentials_meet_login_mins(
            &request.username,
            &request.password,
            shared::validation::LDAP_LOGIN_USERNAME_MIN_FLOOR,
            shared::validation::LDAP_LOGIN_PASSWORD_MIN_FLOOR,
        ));
    }

    #[test]
    fn test_login_request_short_username() {
        let request = LoginRequest {
            username: "ab".to_string(), // Too short (min 3)
            password: "validpassword123".to_string(),
            mfa_code: None,
            csrf_token: None,
        };

        assert!(!shared::validation::credentials_meet_login_mins(
            &request.username,
            &request.password,
            shared::validation::LDAP_LOGIN_USERNAME_MIN_FLOOR,
            shared::validation::LDAP_LOGIN_PASSWORD_MIN_FLOOR,
        ));
    }

    #[test]
    fn test_login_request_short_password() {
        let request = LoginRequest {
            username: "validuser".to_string(),
            password: "short".to_string(), // Too short (min 12)
            mfa_code: None,
            csrf_token: None,
        };

        assert!(!shared::validation::credentials_meet_login_mins(
            &request.username,
            &request.password,
            shared::validation::LDAP_LOGIN_USERNAME_MIN_FLOOR,
            shared::validation::LDAP_LOGIN_PASSWORD_MIN_FLOOR,
        ));
    }

    #[test]
    fn test_login_request_with_mfa_code() {
        let request = LoginRequest {
            username: "validuser".to_string(),
            password: "validpassword123".to_string(),
            mfa_code: Some("123456".to_string()),
            csrf_token: None,
        };

        assert!(shared::validation::credentials_meet_login_mins(
            &request.username,
            &request.password,
            shared::validation::LDAP_LOGIN_USERNAME_MIN_FLOOR,
            shared::validation::LDAP_LOGIN_PASSWORD_MIN_FLOOR,
        ));
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

        assert!(shared::validation::credentials_meet_login_mins(
            &request.username,
            &request.password,
            shared::validation::LDAP_LOGIN_USERNAME_MIN_FLOOR,
            shared::validation::LDAP_LOGIN_PASSWORD_MIN_FLOOR,
        ));
    }

    #[test]
    fn test_login_request_password_minimum_length() {
        let request = LoginRequest {
            username: "validuser".to_string(),
            password: "123456789012".to_string(), // Exactly 12 chars
            mfa_code: None,
            csrf_token: None,
        };

        assert!(shared::validation::credentials_meet_login_mins(
            &request.username,
            &request.password,
            shared::validation::LDAP_LOGIN_USERNAME_MIN_FLOOR,
            shared::validation::LDAP_LOGIN_PASSWORD_MIN_FLOOR,
        ));
    }

    #[test]
    fn test_login_creds_below_mins_warn_literal_pinned() {
        let source = include_str!("auth.rs");
        assert!(
            source.contains(LOGIN_CREDS_BELOW_MINS_WARN),
            "auth.rs must emit the canonical warn literal for below-mins logins"
        );
        // tracing requires a string literal in the macro; pin the const matches it.
        assert_eq!(
            LOGIN_CREDS_BELOW_MINS_WARN,
            "login credentials below configured minimums; LDAPS bind not attempted"
        );
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
        assert!(shared::validation::credentials_meet_login_mins(
            &request.username,
            &request.password,
            shared::validation::LDAP_LOGIN_USERNAME_MIN_FLOOR,
            shared::validation::LDAP_LOGIN_PASSWORD_MIN_FLOOR,
        ));
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
        assert!(shared::validation::credentials_meet_login_mins(
            &request.username,
            &request.password,
            shared::validation::LDAP_LOGIN_USERNAME_MIN_FLOOR,
            shared::validation::LDAP_LOGIN_PASSWORD_MIN_FLOOR,
        ));
    }

    #[test]
    fn test_login_request_unicode_password() {
        let request = LoginRequest {
            username: "testuser".to_string(),
            password: "密码测试密码测试密码测试".to_string(), // 12 unicode chars
            mfa_code: None,
            csrf_token: None,
        };
        assert!(shared::validation::credentials_meet_login_mins(
            &request.username,
            &request.password,
            shared::validation::LDAP_LOGIN_USERNAME_MIN_FLOOR,
            shared::validation::LDAP_LOGIN_PASSWORD_MIN_FLOOR,
        ));
    }

    #[test]
    fn test_login_request_raised_password_min_rejects_mid_length() {
        // Configured floor 20: a 15-char password fails even though >= absolute 12.
        assert!(!shared::validation::credentials_meet_login_mins(
            "validuser",
            "123456789012345", // 15 chars
            3,
            20,
        ));
        assert!(shared::validation::credentials_meet_login_mins(
            "validuser",
            "12345678901234567890", // 20 chars
            3,
            20,
        ));
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
